import { describe, expect, it } from "vitest";
import { ago, auditAction, ms, outcome } from "./format";

describe("format", () => {
  it("describes outcomes in the user's words", () => {
    expect(outcome("sf_to_slack", "created")).toBe("Posted to Slack");
    expect(outcome("slack_to_sf", "created")).toBe("Created in Salesforce");
    expect(outcome("sf_to_slack", "duplicate")).toBe("Duplicate ignored");
  });
  it("formats durations and ages", () => {
    expect(ms(420)).toBe("420 ms");
    expect(ms(2500)).toBe("2.5 s");
    expect(ago(1000, 1010)).toBe("just now");
    expect(ago(0)).toBe("never");
    expect(ago(1000, 1000 + 7200)).toBe("2 h ago");
  });
  it("names audit actions", () => {
    expect(auditAction("connection.salesforce.connected")).toBe("Connected Salesforce");
    expect(auditAction("scim.user.deactivate")).toBe("Okta deactivated a user");
  });
});
