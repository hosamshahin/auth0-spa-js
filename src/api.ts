import { TokenEndpointOptions } from './global';
import { DEFAULT_AUTH0_CLIENT } from './constants';
import { getJSON } from './http';
import { getMissingScope } from './scope';

export type TokenEndpointResponse = {
  id_token: string;
  access_token: string;
  refresh_token?: string;
  expires_in: number;
  scope?: string;
};

export async function oauthToken(
  {
    baseUrl,
    backChannelUrl,
    timeout,
    audience,
    scope,
    auth0Client,
    code,
    code_verifier,
    nonce,
    tokenIssuer,
    grant_type,
    refresh_token,
    ...options
  }: TokenEndpointOptions,
  worker?: Worker
) {
  let url: string = '';
  let body: string = '';
  let formBody: string[] = [];
  let headers: any = {
    'Content-type': 'application/json',
    'Auth0-Client': btoa(JSON.stringify(auth0Client || DEFAULT_AUTH0_CLIENT))
  };

  if (backChannelUrl != undefined) {
    url = `${backChannelUrl}`;
    body = JSON.stringify(options);
    headers['code'] = code;
    headers['code_verifier'] = code_verifier;
    headers['nonce'] = nonce;
    headers['grant_type'] = grant_type;
    headers['refresh_token'] = refresh_token;
  } else if (tokenIssuer && tokenIssuer.includes('cognito')) {
    url = `${baseUrl}/oauth2/token`;
    var details = {
      ...options
    };

    for (var property in details) {
      var encodedKey = encodeURIComponent(property);
      var encodedValue = encodeURIComponent(details[property]);
      formBody.push(encodedKey + '=' + encodedValue);
    }
    formBody.push(`code=${encodeURIComponent(code)}`);
    body = formBody.join('&');
    headers['Content-type'] = 'application/x-www-form-urlencoded';
  } else {
    url = `${baseUrl}/oauth/token`;
    body = JSON.stringify({ ...options, code });
  }

  const result = await getJSON<TokenEndpointResponse>(
    url,
    timeout,
    audience || 'default',
    scope,
    {
      method: 'POST',
      body: body,
      headers: headers
    },
    worker
  );

  const missingScope = getMissingScope(scope, result.scope);
  if (missingScope.length) {
    console.warn(
      `The requested scopes (${scope}) are different from the scopes of the retrieved token (${result.scope}). This could mean that your access token may not include all the scopes that you expect. It is advised to resolve this by either:

  - Removing \`${missingScope}\` from the scope when requesting a new token.
  - Ensuring \`${missingScope}\` is returned as part of the requested token's scopes.`
    );
  }

  return result;
}
