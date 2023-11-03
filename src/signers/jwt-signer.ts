import { DirectSignResponse } from "@cosmjs/proto-signing";
import { SignDoc } from "cosmjs-types/cosmos/tx/v1beta1/tx";
import { sha256 } from "@cosmjs/crypto";
import { AAccountData, AASigner } from "../interfaces/AASigner";
import { AAAlgo } from "../interfaces/smartAccount";
import { getAALastAuthenticatorId } from "./utils";
import { Client } from "stytch";

export const stytchClient = new Client({
  project_id: process.env.NEXT_PUBLIC_STYTCH_PROJECT_ID ?? "",
  secret: process.env.NEXT_PUBLIC_STYTCH_SECRET ?? "",
  env: process.env.NEXT_PUBLIC_STYTCH_API_URL,
});

export class AbstractAccountJWTSigner extends AASigner {
  // requires a session token already created
  sessionToken: string | undefined;
  constructor(abstractAccount: string, sessionToken?: string) {
    super(abstractAccount);
    this.sessionToken = sessionToken;
  }

  async getAccounts(): Promise<readonly AAccountData[]> {
    //TODO: This only needs to check if stytch client can
    // authenticate with whatever auth method is needed
    // assuming that the auth method is already set up
    // we simply return the abstract account data
    if (this.abstractAccount === undefined) {
      return [];
    }

    return [
      {
        address: this.abstractAccount,
        algo: "secp256k1", // we don't really care about this
        pubkey: new Uint8Array(),
        authenticatorId: await getAALastAuthenticatorId(this.abstractAccount),
        accountAddress: this.abstractAccount,
        aaalgo: AAAlgo.JWT,
      },
    ];
  }

  async signDirect(
    signerAddress: string, // this is the email of the user
    signDoc: SignDoc
  ): Promise<DirectSignResponse> {
    if (this.sessionToken === undefined) {
      throw new Error("stytch session token is undefined");
    }
    const signBytes = SignDoc.encode(signDoc).finish();
    const hashSignBytes = sha256(signBytes);
    const message = Buffer.from(hashSignBytes).toString("base64");

    const authResp = await stytchClient.sessions.authenticate({
      session_token: this.sessionToken,
      session_duration_minutes: 60 * 24 * 30,
      session_custom_claims: {
        transaction_hash: message,
      },
    });
    if (authResp.status_code !== 200) {
      throw new Error("Failed to authenticate with stytch");
    }
    return {
      signed: signDoc,
      signature: {
        pub_key: {
          type: "",
          value: new Uint8Array(),
        },
        signature: Buffer.from(authResp.session_jwt, "utf-8").toString(
          "base64"
        ),
      },
    };
  }

  /**
   * This method allows for signing arbitrary messages
   * It does not compose a SignDoc but simply sets the transaction_hash
   * property of the session claims property to the hash of the passed msg
   * @param signerAddress
   * @param message Arbitrary message to be signed
   * @returns
   */
  async signDirectArb(message: string): Promise<{ signature: string }> {
    if (this.sessionToken === undefined) {
      throw new Error("stytch session token is undefined");
    }
    const hashSignBytes = sha256(Buffer.from(message, "utf-8"));
    const hashedMessage = Buffer.from(hashSignBytes).toString("base64");

    const authResp = await stytchClient.sessions.authenticate({
      session_token: this.sessionToken,
      session_duration_minutes: 60 * 24 * 30,
      session_custom_claims: {
        transaction_hash: hashedMessage,
      },
    });
    if (authResp.status_code !== 200) {
      throw new Error("Failed to authenticate with stytch");
    }
    return {
      signature: Buffer.from(authResp.session_jwt, "utf-8").toString("base64"),
    };
  }
}
