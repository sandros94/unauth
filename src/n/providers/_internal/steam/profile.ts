import { getObject } from "../../../flow/_internal/http/json.ts";
import { type Fetch, isRecord, profileError } from "../../../flow/_internal/http/shared.ts";
import type { ProfileResult } from "../../../flow/types.ts";
import { hasMember, nonEmpty } from "../shared.ts";

const PLAYER_SUMMARIES = "https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v2/";

/**
 * A Steam account: its SteamID64 alone when the provider has no Web API key, else the entry of
 * `ISteamUser/GetPlayerSummaries/v2` (https://developer.valvesoftware.com/wiki/Steam_Web_API),
 * whose public members a private profile leaves out.
 */
export interface SteamProfile {
  /** The 17-digit SteamID64. */
  steamid: string;
  personaname?: string;
  profileurl?: string;
  /** 32×32 */
  avatar?: string;
  /** 64×64 */
  avatarmedium?: string;
  /** 184×184 */
  avatarfull?: string;
  avatarhash?: string;
  /** 0 offline, 1 online, 2 busy, 3 away, 4 snooze, 5 looking to trade, 6 looking to play. */
  personastate?: number;
  /** 1 private, 3 public. */
  communityvisibilitystate?: number;
  /** 1 once the community profile is set up. */
  profilestate?: number;
  /** Unix time. */
  lastlogoff?: number;
  realname?: string;
  primaryclanid?: string;
  /** Unix time. */
  timecreated?: number;
  loccountrycode?: string;
  locstatecode?: string;
  loccityid?: number;
  gameid?: string;
  gameextrainfo?: string;
  gameserverip?: string;
  commentpermission?: number;
}

/** The identity of a proven SteamID64, with no Web API key: the SteamID is all there is. */
export function bareIdentity(steamid: string): ProfileResult<SteamProfile> {
  return { subject: steamid, profile: { steamid } };
}

/**
 * The identity of a proven SteamID64 from its player summary, fetched with the Web API key; a
 * summary of another account, or none, is `ERR_AUTHN_PROFILE_INVALID`. The key travels only to
 * the Steam Web API, in the query; a failure's message names the endpoint without it.
 */
export async function playerSummary(
  steamid: string,
  options: { apiKey: string; fetch: Fetch },
): Promise<ProfileResult<SteamProfile>> {
  const url = new URL(PLAYER_SUMMARIES);
  url.searchParams.set("key", options.apiKey);
  url.searchParams.set("steamids", steamid);
  const body = await getObject(url.href, { fetch: options.fetch, label: "Steam Web API" });
  const players = isRecord(body.response) ? body.response.players : undefined;
  const player = Array.isArray(players) ? players[0] : undefined;
  if (!isSteamProfile(player)) {
    throw profileError("The Steam Web API returned no player summary for the signed-in account.");
  }
  if (player.steamid !== steamid) {
    throw profileError("The Steam Web API returned another account than signed in.", {
      expected: steamid,
      steamid: player.steamid,
    });
  }
  const result: ProfileResult<SteamProfile> = { subject: steamid, profile: player };
  const name = nonEmpty(player.personaname);
  if (name !== undefined) result.name = name;
  const avatar =
    nonEmpty(player.avatarfull) ?? nonEmpty(player.avatarmedium) ?? nonEmpty(player.avatar);
  if (avatar !== undefined) result.avatar = avatar;
  return result;
}

function isSteamProfile(value: unknown): value is SteamProfile {
  return hasMember(value, "steamid", "string");
}
