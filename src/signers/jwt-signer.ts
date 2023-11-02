import { DirectSignResponse } from "@cosmjs/proto-signing";
import { SignDoc } from "cosmjs-types/cosmos/tx/v1beta1/tx";
import { sha256 } from "@cosmjs/crypto";
import { AAccountData, AASigner } from "../interfaces/AASigner";
import { AAAlgo } from "../interfaces/smartAccount";
import { getAALastAuthenticatorId } from "./utils";
import stytch from "stytch";

export const stytchClient = new stytch.Client({
  project_id: "project-test-185e9a9f-8bab-42f2-a924-953a59e8ff94",
  secret: "secret-test-u03nhY2N0YF81K19vvSzeTFjvfLV5NCIqGc=",
  env: "https://test.stytch.com/v1",
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
        signature: authResp.session_jwt,
      },
    };
  }
}
