<?php

namespace SocialiteProviders\Zitadel;

use GuzzleHttp\RequestOptions;
use Illuminate\Support\Arr;
use SocialiteProviders\Manager\Exception\InvalidArgumentException;
use SocialiteProviders\Manager\OAuth2\AbstractProvider;
use SocialiteProviders\Manager\OAuth2\User;

class Provider extends AbstractProvider
{
    public const IDENTIFIER = 'ZITADEL';

    protected $scopeSeparator = ' ';

    protected $scopes = ['openid', 'profile', 'email', 'email_verified', 'phone', 'phone_verified', 'address', 'given_name', 'family_name', 'gender', 'locale'];

    /**
     * {@inheritdoc}
     */
    public static function additionalConfigKeys()
    {
        return ['base_url', 'realms'];
    }

    protected function getBaseUrl()
    {
        return rtrim($this->getConfig('base_url'), '/');
    }

    /**
     * {@inheritdoc}
     */
    protected function getAuthUrl($state)
    {
        return $this->buildAuthUrlFromBase($this->getBaseUrl().'/oauth/v2/authorize', $state);
    }

    /**
     * {@inheritdoc}
     */
    protected function getTokenUrl()
    {
        return $this->getBaseUrl().'/oauth/v2/token';
    }

    /**
     * {@inheritdoc}
     */
    protected function getUserByToken($token)
    {
        $response = $this->getHttpClient()->get($this->getBaseUrl().'/oidc/v1/userinfo', [
            RequestOptions::HEADERS => [
                'Authorization' => 'Bearer '.$token,
            ],
        ]);

        return json_decode((string) $response->getBody(), true);
    }

    /**
     * {@inheritdoc}
     */
    protected function mapUserToObject(array $user)
    {
        return (new User())->setRaw($user)->map([
            'id'        => Arr::get($user, 'sub'),
            'nickname'  => Arr::get($user, 'preferred_username'),
            'name'      => Arr::get($user, 'name'),
            'given_name'      => Arr::get($user, 'given_name'),
            'family_name'      => Arr::get($user, 'family_name'),
            'email'     => Arr::get($user, 'email'),
            'email_verified'     => Arr::get($user, 'email_verified'),
            'gender'     => Arr::get($user, 'gender'),
            'locale'     => Arr::get($user, 'locale'),
            'phone'     => Arr::get($user, 'phone'),
            'phone_verified'     => Arr::get($user, 'phone_verified'),
        ]);
    }

    /**
     * Return logout endpoint with redirect_uri, clientId, idTokenHint
     * and optional parameters by a key value array.
     *
     * @param  string|null  $redirectUri
     * @param  string|null  $clientId
     * @param  string|null  $idTokenHint
     * @param  array  $additionalParameters
     * @return string
     *
     * @throws InvalidArgumentException
     */
    public function getLogoutUrl(?string $redirectUri = null, ?string $clientId = null, ?string $idTokenHint = null, ...$additionalParameters): string
    {
        $logoutUrl = $this->getBaseUrl().'/oidc/v1/end_session';

        // Keycloak v18+ or before
        if ($redirectUri === null) {
            return $logoutUrl;
        }

        // Before Keycloak v18
        if ($clientId === null && $idTokenHint === null) {
            return $logoutUrl.'?redirect_uri='.urlencode($redirectUri);
        }

        // https://zitadel.com/docs/guides/integrate/logout
        // https://openid.net/specs/openid-connect-rpinitiated-1_0.html
        $logoutUrl .= '?post_logout_redirect_uri='.urlencode($redirectUri);

        // Either clientId or idTokenHint
        // is required for the post redirect to work.
        if ($clientId !== null) {
            $logoutUrl .= '&client_id='.urlencode($clientId);
        }

        if ($idTokenHint !== null) {
            $logoutUrl .= '&id_token_hint='.urlencode($idTokenHint);
        }

        foreach ($additionalParameters as $parameter) {
            if (! is_array($parameter) || count($parameter) > 1) {
                throw new InvalidArgumentException('Invalid argument. Expected an array with a key and a value.');
            }

            $parameterKey = array_keys($parameter)[0];
            $parameterValue = array_values($parameter)[0];

            $logoutUrl .= "&{$parameterKey}=".urlencode($parameterValue);
        }

        return $logoutUrl;
    }
}
