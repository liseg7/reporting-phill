import { KeyManagementServiceClient } from "@google-cloud/kms";
import { Crc32c } from "@aws-crypto/crc32c";
import { match, P } from "ts-pattern";

const client = new KeyManagementServiceClient();

export async function encrypt(
  buffer: Uint8Array,
  key: string
): Promise<Uint8Array> {
  const crc32Digest = new Crc32c().update(buffer).digest();

  const [response] = await client.encrypt({
    name: key,
    plaintext: buffer,
    plaintextCrc32c: {
      value: crc32Digest,
    },
  });

  if (!response.ciphertext) {
    throw new Error("Ciphertext was not returned from KMS");
  }

  if (!response.verifiedPlaintextCrc32c) {
    throw new Error("CRC32C check failed. Request corrupted in transit.");
  }

  const ciphertextBuffer = match(response.ciphertext)
    .with(P.string, new TextEncoder().encode)
    .otherwise((buff) => buff);

  if (
    new Crc32c().update(ciphertextBuffer).digest() !==
    Number(response.ciphertextCrc32c?.value)
  ) {
    throw new Error(
      "Ciphertext CRC32C mismatch. Response corrupted in transit."
    );
  }

  return ciphertextBuffer;
}

export async function decrypt(
  ciphertext: Uint8Array,
  key: string
): Promise<Uint8Array> {
  const crc32Digest = new Crc32c().update(ciphertext).digest();

  const [response] = await client.decrypt({
    name: key,
    ciphertext: ciphertext,
    ciphertextCrc32c: {
      value: crc32Digest,
    },
  });

  if (!response.plaintext) {
    throw new Error("Plaintext was not returned from KMS");
  }

  const plaintextBuffer = match(response.plaintext)
    .with(P.string, new TextEncoder().encode)
    .otherwise((buff) => buff);

  if (
    new Crc32c().update(plaintextBuffer).digest() !==
    Number(response.plaintextCrc32c?.value)
  ) {
    throw new Error(
      "Plaintext CRC32C mismatch. Response corrupted in transit."
    );
  }

  return plaintextBuffer;
}
