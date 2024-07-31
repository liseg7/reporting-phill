import { z } from "zod";
import { Hono } from "hono";
import { Database } from "bun:sqlite";
import { getCookie, setCookie } from "hono/cookie";
import { pipe } from "remeda";
import { base64ToString, stringToBase64 } from "uint8array-extras";
import { ChatOpenAI } from "@langchain/openai";
import { ChatPromptTemplate } from "@langchain/core/prompts";
import { StringOutputParser } from "@langchain/core/output_parsers";
import * as auth from "./auth/index.js";
import { nanoid } from "nanoid";
import { Octokit } from "octokit";
import { paginateGraphQL } from "@octokit/plugin-paginate-graphql";
import type {
  PullRequest,
  SearchResultItemConnection,
} from "@octokit/graphql-schema";
import {
  createOAuthUserAuth,
  type GitHubAppStrategyOptionsExistingAuthenticationWithExpiration,
} from "@octokit/auth-oauth-user";
import { decrypt, encrypt } from "./crypto.js";

const seconds = {
  minute: 60,
  hour: 60 * 60,
  day: 60 * 60 * 24,
  week: 60 * 60 * 24 * 7,
};

const ENV_SCHEMA = z.object({
  GITHUB_OAUTH_CLIENT_ID: z.string(),
  GITHUB_OAUTH_CLIENT_SECRET: z.string(),
  OPENAI_API_KEY: z.string(),
});

const values = ENV_SCHEMA.parse(process.env);

export const config = {
  oauth: {
    github: {
      clientID: values.GITHUB_OAUTH_CLIENT_ID,
      secret: values.GITHUB_OAUTH_CLIENT_SECRET,
    },
  },
  key: "projects/phill-1599571548621/locations/europe-west1/keyRings/tokens/cryptoKeys/github",
  open_ai_key: values.OPENAI_API_KEY,
};

// epoch - milliseconds
export const accessTokenMap = new Map<
  string,
  { accessToken: string; expiresEpoch: number }
>();

const address = new URL("http://localhost:4000");
const GITHUB_CALLBACK = new URL("/auth/github/callback", address);

const authz = {
  github: auth.GitHub({
    clientID: config.oauth.github.clientID,
    clientSecret: config.oauth.github.secret,
    scope: "user:email read:user",
    redirectURI: GITHUB_CALLBACK.toString(),
    logger: console,
  }),
};

export function getGitHubClient() {
  const client = Octokit.plugin(paginateGraphQL);
  return client;
}

const app = new Hono();

const db = new Database("db.sqlite");

db.query(
  `create table if not exists "tokens" ( user_id text primary key, refresh_token text, expiration_date number, user_name string );`
).all();

app.get("/", (c) => {
  const userID = c.req.query("user_id") || `u_${nanoid()}`;

  return c.html(`
		<body>
			<p> Your user id is ${userID} </p>
			<a href="/auth/github/authorize?user_id=${userID}"> Link GitHub </a>
      &nbsp
			<a href="/tokens?user_id=${userID}"> See my tokens </a>
      &nbsp
      <a href="/commits?user_id=${userID}"> See my commits </a>
      &nbsp
      <a href="/prs?user_id=${userID}"> See my pull requests </a>
      &nbsp
      <a href="/summary?user_id=${userID}"> Summary of what I did today! </a>
		</body>
		`);
});

app.get("/auth/github/authorize", async (c) => {
  const userID = c.req.query("user_id");

  if (!userID) {
    return c.json("Unauthorized", 401);
  }
  const { state, url } = await authz.github.authorize();

  const secure = c.req.url.startsWith("https://");

  const value = pipe(state, JSON.stringify, stringToBase64);
  setCookie(c, "state", value, {
    maxAge: 10 * seconds.minute,
    httpOnly: true,
    ...(secure ? { secure: secure, sameSite: "none" } : {}),
  });
  const valueUser = pipe(userID, JSON.stringify, stringToBase64);
  setCookie(c, "user", valueUser, {
    maxAge: 10 * seconds.minute,
    httpOnly: true,
    ...(secure ? { secure: secure, sameSite: "none" } : {}),
  });

  return c.redirect(url.toString());
});

app.get("/auth/github/callback", async (c) => {
  const cookie = getCookie(c, "state");
  const userID = getCookie(c, "user");

  if (!userID) {
    return c.json({ message: "unauthorized" }, { status: 401 });
  }

  if (!cookie) {
    return c.json({ message: "No state" }, { status: 400 });
  }

  const state = pipe(cookie, base64ToString, JSON.parse);
  const response = await authz.github.callback(
    new URL(c.req.url),
    state,
    GITHUB_CALLBACK.toString()
  );

  const currentTimestamp = Date.now();

  const refreshTokenExpirationTimestamp =
    currentTimestamp + (response.refresh_token_expires_in as number) * 1000;

  const octokit = new Octokit({ auth: response.access_token });
  const userName = (await octokit.request("GET /user")).data.login;

  const bytes = await encrypt(
    new TextEncoder().encode(response.refresh_token),
    config.key
  );
  const buffer = Buffer.from(bytes);
  const base64String = buffer.toString("base64");

  db.query(
    "insert into tokens (user_id, refresh_token, expiration_date, user_name) values ($userId, $refreshToken, $expirationDateToken, $userName)"
  ).all({
    $userId: userID!,
    $refreshToken: base64String,
    $expirationDateToken: refreshTokenExpirationTimestamp,
    $userName: userName,
  });

  const accessTokenExpirationTimestamp =
    currentTimestamp + (response.expires_in as number) * 1000;
  accessTokenMap.set(userID, {
    accessToken: response.access_token,
    expiresEpoch: accessTokenExpirationTimestamp,
  });
  return c.redirect(`/?user_id=${userID}`);
});

app.get("tokens", async (c) => {
  const userID = c.req.query("user_id");

  if (!userID) {
    return c.json("Unauthorized", 401);
  }

  const rows = await db
    .query("select * from tokens where user_id = $userID")
    .all({ $userID: userID });

  return c.json(rows);
});

app.get("commits", async (c) => {
  const userID = c.req.query("user_id");

  if (!userID) {
    return c.json({ message: "unauthorized" }, { status: 401 });
  }

  const rows = (await db
    .query("select * from tokens where user_id = $userID")
    .all({ $userID: userID as string })) as TokenRow[];

  if (rows.length === 0) {
    return c.json("Unauthorized", 401);
  }

  const { refresh_token, expiration_date } = rows[0];

  const bytes = pipe(
    refresh_token,
    (x) => Buffer.from(x, "base64"),
    (buffer) =>
      new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength)
  );
  const refreshToken = new TextDecoder().decode(
    await decrypt(bytes, config.key)
  );

  let accessToken = "";
  let accessTokenExpiration: string = new Date().toISOString();
  const token = accessTokenMap.get(userID);
  if (token && token.expiresEpoch > Date.now()) {
    accessToken = token.accessToken;
    accessTokenExpiration = new Date(token.expiresEpoch).toISOString();
  }

  const Client = getGitHubClient();
  let client = new Client({
    authStrategy: createOAuthUserAuth,
    auth: {
      clientType: "github-app",
      clientId: config.oauth.github.clientID,
      clientSecret: config.oauth.github.secret,
      token: accessToken,
      refreshToken: refreshToken,
      expiresAt: accessTokenExpiration,
      refreshTokenExpiresAt: new Date(expiration_date).toISOString(),
    } satisfies GitHubAppStrategyOptionsExistingAuthenticationWithExpiration,
  });

  const [start, end] = await getDates();

  // THIS PART NEEDS TO BE SET IN PHILL BASED UPON WHICH REPO THEY CHOOSE
  const repoName = "alumni-api";
  const message: ListMessage = {
    repo: repoName,
    since: start,
    until: end,
    author: rows[0].user_name,
    owner: "Panenco",
  };

  const listCommits = await paginatedCommits(client, message);
  const summary = await summarizeCommits(listCommits, repoName);

  return c.text(summary);
});

app.get("prs", async (c) => {
  const userID = c.req.query("user_id");

  if (!userID) {
    return c.json({ message: "unauthorized" }, { status: 401 });
  }

  const rows = (await db
    .query("select * from tokens where user_id = $userID")
    .all({ $userID: userID as string })) as TokenRow[];

  if (rows.length === 0) {
    return c.json("Unauthorized", 401);
  }

  const { refresh_token, expiration_date } = rows[0];

  let accessToken = "";
  let accessTokenExpiration: string = new Date().toISOString();
  const token = accessTokenMap.get(userID);
  if (token && token.expiresEpoch > Date.now()) {
    accessToken = token.accessToken;
    accessTokenExpiration = new Date(token.expiresEpoch).toISOString();
  }

  const bytes = pipe(
    refresh_token,
    (x) => Buffer.from(x, "base64"),
    (buffer) =>
      new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength)
  );
  const refreshToken = new TextDecoder().decode(
    await decrypt(bytes, config.key)
  );

  const Client = getGitHubClient();
  const client = new Client({
    authStrategy: createOAuthUserAuth,
    auth: {
      clientType: "github-app",
      clientId: config.oauth.github.clientID,
      clientSecret: config.oauth.github.secret,
      token: accessToken,
      refreshToken: refreshToken,
      expiresAt: accessTokenExpiration,
      refreshTokenExpiresAt: new Date(expiration_date).toISOString(),
    } satisfies GitHubAppStrategyOptionsExistingAuthenticationWithExpiration,
  });

  const [start, end] = await getDates();

  // NEEDS TO BE SET IN PHILL
  const repoName = "alumni-api";
  const message: ListMessage = {
    repo: repoName,
    since: start,
    until: end,
    author: rows[0].user_name,
    owner: "Panenco",
  };

  const listPrs = await listPullRequests(client, message);

  return c.text(await summarizePrs(listPrs, repoName));
});

app.get("summary", async (c) => {
  const userID = c.req.query("user_id");

  if (!userID) {
    return c.json({ message: "unauthorized" }, { status: 401 });
  }

  const rows = (await db
    .query("select * from tokens where user_id = $userID")
    .all({ $userID: userID as string })) as TokenRow[];

  if (rows.length === 0) {
    return c.json("Unauthorized", 401);
  }
  const { refresh_token, expiration_date } = rows[0];

  if (new Date(rows[0].expiration_date) < new Date()) {
    throw "refresh token has expired log in again";
  }

  const bytes = pipe(
    refresh_token,
    (x) => Buffer.from(x, "base64"),
    (buffer) =>
      new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength)
  );
  const refreshToken = new TextDecoder().decode(
    await decrypt(bytes, config.key)
  );

  let accessToken = "";
  let accessTokenExpiration: string = new Date().toISOString();
  const token = accessTokenMap.get(userID);
  if (token && token.expiresEpoch > Date.now()) {
    accessToken = token.accessToken;
    accessTokenExpiration = new Date(token.expiresEpoch).toISOString();
  }

  const Client = getGitHubClient();
  const client = new Client({
    authStrategy: createOAuthUserAuth,
    auth: {
      clientType: "github-app",
      clientId: config.oauth.github.clientID,
      clientSecret: config.oauth.github.secret,
      token: accessToken,
      refreshToken: refreshToken,
      expiresAt: accessTokenExpiration,
      refreshTokenExpiresAt: new Date(expiration_date).toISOString(),
    } satisfies GitHubAppStrategyOptionsExistingAuthenticationWithExpiration,
  });

  const [start, end] = await getDates();

  // NEEDS TO BE SET IN PHILL
  const repoName = "alumni-api";
  const message: ListMessage = {
    repo: repoName,
    since: start,
    until: end,
    author: rows[0].user_name,
    owner: "Panenco",
  };

  const listPrs = await listPullRequests(client, message);
  const listCommits = await paginatedCommits(client, message);

  return c.text(await summarize(listPrs, listCommits, repoName));
});

interface TokenRow {
  user_id: string;
  refresh_token: string;
  expiration_date: number;
  user_name: string;
}

/*
Utility function for LSP to kick-in
 */
function graphql(query: string) {
  return query;
}

type ListMessage = {
  repo: string;
  since: string;
  until: string;
  author: string;
  owner: string;
};

async function listPullRequests(
  client: Octokit,
  message: ListMessage
): Promise<string> {
  const query = graphql(`
		query paginate($cursor: String) {
			search(query: "is:pr author:${message.author} created:${message.since}..${message.until} repo:${message.owner}/${message.repo}",  type: ISSUE, first: 100, after: $cursor) {
				nodes {
					... on PullRequest {
						title
						state
						url
						createdAt
            body
            author{
                login
                }
						repository {
							nameWithOwner
						}  
					}
				}
				pageInfo {
					endCursor
					hasNextPage
				}
			}
		}
	`);

  const iterator = client.graphql.paginate.iterator<{
    search: SearchResultItemConnection;
  }>(query);

  const prs: PullRequest[] = [];
  // iterate over pages
  for await (const response of iterator) {
    const { nodes } = response.search;
    if (!nodes || nodes.length === 0) break;

    prs.push(...(nodes as PullRequest[]));
  }

  let listPrs = prs.map((pr) => pr.body).join(", ");

  return listPrs;
}

export const getDates = async () => {
  const since = new Date();
  since.setHours(0, 0, 0);
  since.setDate(20); //THIS IS USED FOR TESTING REMOVE IN PHILL
  const until = new Date();
  until.setHours(23, 59, 59);
  return [since.toISOString(), until.toISOString()];
};

export const paginatedCommits = async (
  client: Octokit,
  message: ListMessage
) => {
  const iterator = client.paginate.iterator(client.rest.repos.listCommits, {
    owner: message.owner,
    repo: message.repo,
    author: message.author,
    since: message.since,
    until: message.until,
    per_page: 100,
  });

  const commitMessages = [];
  for await (const { data: commits } of iterator) {
    commitMessages.push(...commits.map((commit) => commit.commit.message));
  }
  return commitMessages.join(", ");
};

async function summarizeCommits(list_commits: string, repo_name: string) {
  const prompt = ChatPromptTemplate.fromMessages([
    [
      "human",
      `If the list {commits} is empty say: I didn't work on the {repo_name} today. Don't say anything else.
       Else if the list of {commits} is NOT empty:
       Summarize the given list of commit messages {commits} that a person made in a repository {repo_name} today in first person.
       Be as specific and as concise as possible based on the commit messages.
      In no more than 5 bullet points while only mentioning the most important commits which have the biggest impact on the repository.
       If some parts of the list seem redundant remove them. Don't add extra sentences explaining the structure of the response.
       
       Format the output as follows:
       First give one sentence summarizing all the commits in {commits}. 
       Second say "More specifically the following actions were undertaken: "
       Third give a list of the 5 most important commits made {commits} use bullet points and choosing the most important commits to mention.
        
       Example of a good structure:
       One sentence summarizing what I did today based upon {commits} in first person.
       More specifically the following actions were undertaken:
        -  important element of the commits
        -  important element of the commits
        -  important element of the commits
        -  important element of the commits
        -  important element of the commits
       `,
    ],
  ]);

  const model = new ChatOpenAI({});
  const outputParser = new StringOutputParser();

  const chain = prompt.pipe(model).pipe(outputParser);

  const response = await chain.invoke({
    repo_name: repo_name,
    commits: list_commits,
  });

  return response;
}

async function summarize(
  list_prs: string,
  list_commits: string,
  repo_name: string
) {
  const prompt = ChatPromptTemplate.fromMessages([
    [
      "human",
      `If the list {commits} and {prs} is empty say: I didn't work on the {repo_name} today. Don't say anything else.
      Else if the list of {commits} and {prs} is NOT empty:
       Summarize the given list of commit messages {commits} and pull requests {prs} that a person made in a repository {repo_name} today in first person.
       Be as specific and as concise as possible based on the messages.
      In no more than 5 bullet points while only mentioning the most important changes which have the biggest impact on the repository.
       If some parts of the list seem redundant remove them. Don't add extra sentences explaining the structure of the response.
       
       Format the output as follows:
       First give one sentence summarizing all the commits in {commits} and pull requests in {prs}. 
       Second say "More specifically the following actions were undertaken: "
       Third give a list of the 5 most important commits made {commits} and pull requests made {prs} use bullet points and choosing the most important commits and pull requests to mention.
        
       Example of a good structure:
       One sentence summarizing what I did today based on the commits and pull requests in first person.
       More specifically the following actions were undertaken:
        -  important element of the commits/pull request
        -  important element of the commits/pull request
        -  important element of the commits/pull request
        -  important element of the commits/pull request
        -  important element of the commits/pull request
       `,
    ],
  ]);

  const model = new ChatOpenAI({});
  const outputParser = new StringOutputParser();

  const chain = prompt.pipe(model).pipe(outputParser);

  const response = await chain.invoke({
    repo_name: repo_name,
    commits: list_commits,
    prs: list_prs,
  });

  return response;
}

async function summarizePrs(list_prs: string, repo_name: string) {
  const prompt = ChatPromptTemplate.fromMessages([
    [
      "human",
      `If the list {prs} is empty say: I didn't work on the {repo_name} today. Don't say anything else.
       Else if the list {prs} is NOT empty:
       Summarize the given list of pull request messages {prs} that a person made in a repository {repo_name} today in first person.
       Be as specific and as concise as possible based on the pull request message.
      In no more than 5 bullet points while only mentioning the most important pull requests which have the biggest impact on the repository.
       If some parts of the list seem redundant remove them. Don't add extra sentences explaining the structure of the response.
       
       Format the output as follows:
       First give one sentence summarizing all the prs in {prs}. 
       Second say "More specifically the following actions were undertaken: "
       Third give a list of the 5 most important prs made {prs} use bullet points and choosing the most important prs to mention.
        
       Example of a good structure:
       One sentence summarizing what I did today based on the prs in first person.
       More specifically the following actions were undertaken:
        -  important element of the prs
        -  important element of the prs
        -  important element of the prs
        -  important element of the prs
        -  important element of the prs
       `,
    ],
  ]);

  const model = new ChatOpenAI({});
  const outputParser = new StringOutputParser();

  const chain = prompt.pipe(model).pipe(outputParser);

  const response = await chain.invoke({
    repo_name: repo_name,
    prs: list_prs,
  });

  return response;
}

console.log(`Listening on ${address}`);

export default {
  port: address.port,
  fetch: app.fetch,
};
