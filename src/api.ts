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
    tokenIssuer,
    ...options
  }: TokenEndpointOptions,
  worker?: Worker
) {
  let url: string = '';
  let body: string = '';
  let contentType: string = '';
  let formBody: string[] = [];

  if (backChannelUrl != undefined) {
    url = `${backChannelUrl}?code=${code}`;
    body = JSON.stringify(options);
    contentType = 'application/json';
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
    contentType = 'application/x-www-form-urlencoded';
  } else {
    url = `${baseUrl}/oauth/token`;
    body = JSON.stringify({ ...options, code });
    contentType = 'application/json';
  }

  const result = await getJSON<TokenEndpointResponse>(
    url,
    timeout,
    audience || 'default',
    scope,
    {
      method: 'POST',
      body: body,
      headers: {
        'Content-type': contentType,
        'Auth0-Client': btoa(
          JSON.stringify(auth0Client || DEFAULT_AUTH0_CLIENT)
        )
      }
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
