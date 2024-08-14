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
import { refreshToken as refreshTokenFunction } from "@octokit/oauth-methods";
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
  cryptoKey:
    "projects/phill-1599571548621/locations/europe-west1/keyRings/tokens/cryptoKeys/github",
  openAiKey: values.OPENAI_API_KEY,
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
			<a href="/api/auth/github/authorize?user_id=${userID}"> Link GitHub </a>
      &nbsp
			<a href="/api/tokens?user_id=${userID}"> See my tokens </a>
      &nbsp
      <a href="/api/commits?user_id=${userID}"> See my commits </a>
      &nbsp
      <a href="/api/prs?user_id=${userID}"> See my pull requests </a>
      &nbsp
      <a href="/api/summary?user_id=${userID}"> Summary of what I did today! </a>
		</body>
		`);
});

app.get("/api/auth/github/authorize", async (c) => {
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
  console.log(response.refresh_token);

  const bytes = await encrypt(
    new TextEncoder().encode(response.refresh_token),
    config.cryptoKey
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
    await decrypt(bytes, config.cryptoKey)
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
  const message: Message = {
    repo: repoName,
    since: start,
    until: end,
    author: rows[0].user_name,
    owner: "Panenco",
  };

  const commits = await getCommitsDescriptions(client, message);
  const summary = await summarizeCommits(commits.join(" ,"), repoName);

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
    await decrypt(bytes, config.cryptoKey)
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
  const message: Message = {
    repo: repoName,
    since: start,
    until: end,
    author: rows[0].user_name,
    owner: "Panenco",
  };

  const prs = await getPullRequestsDescriptions(client, message);

  return c.text(await summarizePrs(prs.join(","), repoName));
});

app.get("/api/summary", async (c) => {
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
    await decrypt(bytes, config.cryptoKey)
  );

  let accessToken = "";
  let accessTokenExpiration: string = new Date().toISOString();
  const token = accessTokenMap.get(userID);
  if (token && token.expiresEpoch > Date.now()) {
    accessToken = token.accessToken;
    accessTokenExpiration = new Date(token.expiresEpoch).toISOString();
  }

  const { data, authentication } = await refreshTokenFunction({
    clientType: "github-app",
    clientId: config.oauth.github.clientID,
    clientSecret: config.oauth.github.secret,
    refreshToken: refreshToken,
  });

  const currentTimestamp = Date.now();

  const accessTokenExpirationTimestamp =
    currentTimestamp + (data.expires_in as number) * 1000;
  const Client = getGitHubClient();
  const client = new Client({
    authStrategy: createOAuthUserAuth,
    auth: {
      clientType: "github-app",
      clientId: config.oauth.github.clientID,
      clientSecret: config.oauth.github.secret,
      token: data.access_token,
      refreshToken: refreshToken,
      expiresAt: new Date(accessTokenExpirationTimestamp).toISOString(),
      refreshTokenExpiresAt: new Date(expiration_date).toISOString(),
    } satisfies GitHubAppStrategyOptionsExistingAuthenticationWithExpiration,
  });

  const [start, end] = await getDates();

  // NEEDS TO BE SET IN PHILL
  const repoName = "reporting-phill";
  const message: Message = {
    repo: repoName,
    since: start,
    until: end,
    author: rows[0].user_name,
    owner: "liseg7",
  };

  const prs = await getPullRequestsDescriptions(client, message);

  const commits = await getCommitsDescriptions(client, message);

  return c.text(await summarize(prs.join(","), commits.join(","), repoName));
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

type Message = {
  repo: string;
  since: string;
  until: string;
  author: string;
  owner: string;
};

async function getPullRequestsDescriptions(
  client: Octokit,
  message: Message
): Promise<string[]> {
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

  const listPrs: PullRequest[] = [];
  // iterate over pages
  for await (const response of iterator) {
    const { nodes } = response.search;
    if (!nodes || nodes.length === 0) break;

    listPrs.push(...(nodes as PullRequest[]));
  }

  let prs = listPrs.map((pr) => pr.title + pr.body);

  return prs;
}

export const getDates = async () => {
  const since = new Date();
  since.setHours(0, 0, 0);
  since.setMonth(6); //THIS IS USED FOR TESTING REMOVE IN PHILL
  const until = new Date();
  until.setHours(23, 59, 59);
  return [since.toISOString(), until.toISOString()];
};

export const getCommitsDescriptions = async (
  client: Octokit,
  message: Message
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
  return commitMessages;
};

async function summarizeCommits(commits: string, repoName: string) {
  const prompt = ChatPromptTemplate.fromMessages([
    [
      "human",
      `If the list {commits} is empty only say: I didn't work on the {repo_name} today. 
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
    repo_name: repoName,
    commits: commits,
  });

  return response;
}

async function summarize(prs: string, commits: string, repoName: string) {
  console.log("commits", commits);
  console.log("prs", prs);

  const prompt = ChatPromptTemplate.fromMessages([
    [
      "human",
      `If the list {commits} and {prs} is empty only say: I didn't work on {repo_name} today.
      Else if the list of {commits} and {prs} is NOT empty:
       Summarize the given list of commit messages {commits} and pull requests {prs} that a person made in a repository {repo_name} today in first person.
       Be as specific and as concise as possible based on the messages. Summarize everything in 2 short sentences by only mentioning the most important parts. 
       The shorter the sentences the better.
    
       `,
    ],
  ]);

  const model = new ChatOpenAI({});
  const outputParser = new StringOutputParser();

  const chain = prompt.pipe(model).pipe(outputParser);

  const response = await chain.invoke({
    repo_name: repoName,
    commits: commits,
    prs: prs,
  });

  return response;
}

async function summarizePrs(prs: string, repoName: string) {
  const prompt = ChatPromptTemplate.fromMessages([
    [
      "human",
      `If the list {prs} is empty only say: I didn't work on {repo_name} today.
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
    repo_name: repoName,
    prs: prs,
  });

  return response;
}

console.log(`Listening on ${address}`);

export default {
  port: address.port,
  fetch: app.fetch,
};
