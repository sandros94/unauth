/**
 * Account payloads in the shape each provider documents, with made-up values. Profile tests map
 * them without any network.
 */

export const githubUser = {
  login: "octocat",
  id: 583231,
  node_id: "MDQ6VXNlcjU4MzIzMQ==",
  avatar_url: "https://avatars.githubusercontent.com/u/583231?v=4",
  html_url: "https://github.com/octocat",
  type: "User",
  site_admin: false,
  name: "The Octocat",
  company: "@github",
  blog: "https://github.blog",
  location: "San Francisco",
  email: null,
  bio: null,
  twitter_username: null,
  public_repos: 8,
  followers: 20000,
  following: 9,
  created_at: "2011-01-25T18:44:36Z",
  updated_at: "2026-09-22T11:25:21Z",
};

export const githubEmails = [
  { email: "octocat@users.noreply.github.com", primary: false, verified: true, visibility: null },
  { email: "octocat@github.com", primary: true, verified: true, visibility: "private" },
] as const;

export const googleClaims = {
  iss: "https://accounts.google.com",
  azp: "client-1",
  aud: "client-1",
  sub: "110169484474386276334",
  hd: "example.com",
  email: "ada@example.com",
  email_verified: true,
  at_hash: "HK6E_P6Dh8Y93mRNtsDB1Q",
  nonce: "n1",
  name: "Ada Lovelace",
  picture: "https://lh3.googleusercontent.com/a/photo.jpg",
  given_name: "Ada",
  family_name: "Lovelace",
  iat: 1790856000,
  exp: 1790859600,
};

export const discordUser = {
  id: "80351110224678912",
  username: "nelly",
  discriminator: "0",
  global_name: "Nelly",
  avatar: "8342729096ea3675442027381ff50dfe",
  verified: true,
  email: "nelly@discord.com",
  flags: 64,
  banner: null,
  accent_color: 16711680,
  premium_type: 1,
  public_flags: 64,
  mfa_enabled: true,
  locale: "en-US",
};

export const microsoftUser = {
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#users/$entity",
  "businessPhones": ["+1 412 555 0109"],
  "displayName": "Megan Bowen",
  "givenName": "Megan",
  "jobTitle": "Auditor",
  "mail": "MeganB@contoso.com",
  "mobilePhone": null,
  "officeLocation": "12/1110",
  "preferredLanguage": "en-US",
  "surname": "Bowen",
  "userPrincipalName": "MeganB@contoso.com",
  "id": "48d31887-5fad-4d73-a9f5-3c356e68a038",
} as const;

export const appleClaims = {
  iss: "https://appleid.apple.com",
  aud: "com.example.web",
  exp: 1790859600,
  iat: 1790856000,
  sub: "001234.5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c.1234",
  nonce: "n1",
  at_hash: "abc",
  email: "x7k2@privaterelay.appleid.com",
  email_verified: "true",
  is_private_email: "true",
  auth_time: 1790856000,
  nonce_supported: true,
};

export const appleFirstLoginUser: string = JSON.stringify({
  name: { firstName: "Ada", lastName: "Lovelace" },
  email: "x7k2@privaterelay.appleid.com",
});

export const gitlabUser = {
  id: 1,
  username: "john_smith",
  name: "John Smith",
  state: "active",
  locked: false,
  avatar_url: "https://gitlab.com/uploads/user/avatar/1/cd8.jpeg",
  web_url: "https://gitlab.com/john_smith",
  created_at: "2012-05-23T08:00:58Z",
  bio: "",
  location: null,
  public_email: "john@example.com",
  email: "john@example.com",
  two_factor_enabled: true,
};

export const twitchUsers = {
  data: [
    {
      id: "141981764",
      login: "twitchdev",
      display_name: "TwitchDev",
      type: "",
      broadcaster_type: "partner",
      description: "Supporting third-party developers building Twitch integrations.",
      profile_image_url:
        "https://static-cdn.jtvnw.net/jtv_user_pictures/8a6381c7-profile_image-300x300.png",
      offline_image_url:
        "https://static-cdn.jtvnw.net/jtv_user_pictures/3f13ab61-channel_offline_image-1920x1080.png",
      view_count: 5980557,
      email: "not-real@email.com",
      created_at: "2016-12-14T20:32:28Z",
    },
  ],
} as const;

export const linkedinClaims = {
  iss: "https://www.linkedin.com/oauth",
  aud: "client-1",
  iat: 1790856000,
  exp: 1790859600,
  sub: "782bbtaQ",
  name: "John Doe",
  given_name: "John",
  family_name: "Doe",
  picture:
    "https://media.licdn-ei.com/dms/image/C5F03AQHqK8v7tB1HCQ/profile-displayphoto-shrink_100_100/0/",
  locale: { country: "US", language: "en" },
  email: "doe@email.com",
  email_verified: true,
};

export const facebookUser = {
  id: "10224354126445211",
  name: "Ada Lovelace",
  email: "ada@example.com",
  picture: {
    data: {
      height: 50,
      is_silhouette: false,
      url: "https://platform-lookaside.fbsbx.com/platform/profilepic/?asid=10224354126445211",
      width: 50,
    },
  },
};

export const xUsersMe = {
  data: {
    id: "2244994945",
    name: "Developers",
    username: "XDevelopers",
    profile_image_url:
      "https://pbs.twimg.com/profile_images/1683325380441128960/yRsRRjGO_normal.jpg",
    description: "The voice of the X Dev team.",
    verified: true,
    verified_type: "business",
    created_at: "2013-12-14T04:35:55.000Z",
  },
};
