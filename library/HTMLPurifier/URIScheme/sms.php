<?php

/**
 * Validates sms (for text messaging).
 *
 * The relevant specification for this protocol is RFC 5724.
 * This class normalizes SMS numbers so that they only include
 * digits, optionally with a leading plus for international numbers.
 *
 * According to RFC 5724, SMS URIs support the 'body' parameter
 * using the format: sms:number?body=message
 * However, the format: sms:number&body=message is commonly used on
 * the web, so it is also supported here.
 */

class HTMLPurifier_URIScheme_sms extends HTMLPurifier_URIScheme
{
    /**
     * @type bool
     */
    public $browsable = false;

    /**
     * @type bool
     */
    public $may_omit_host = true;

    /**
     * @param HTMLPurifier_URI $uri
     * @param HTMLPurifier_Config $config
     * @param HTMLPurifier_Context $context
     * @return bool
     */
    public function doValidate(&$uri, $config, $context)
    {
        $uri->userinfo = null;
        $uri->host     = null;
        $uri->port     = null;

        // Handle SMS URIs with &body= syntax (non-standard but common)
        if (strpos($uri->path, '&body=') !== false) {
            $parts = explode('&body=', $uri->path, 2);
            $phone_number = $parts[0];
            $body_content = isset($parts[1]) ? $parts[1] : '';

            // Clean the phone number part
            $phone_number = preg_replace(
                '/(?!^\+)[^\d]/',
                '',
                rawurldecode($phone_number)
            );

            // Sanitize the body content
            $body_content = $this->sanitizeBody($body_content);

            // Reconstruct the path
            if (!empty($body_content)) {
                $uri->path = $phone_number . '&body=' . $body_content;
            } else {
                $uri->path = $phone_number;
            }
        } else {
            // Clean the phone number (no body parameter)
            $uri->path = preg_replace(
                '/(?!^\+)[^\d]/',
                '',
                rawurldecode($uri->path)
            );
        }

        // Handle standard ?body= syntax in query parameters
        if (!is_null($uri->query) && strpos($uri->query, 'body=') === 0) {
            $body_content = substr($uri->query, 5); // Remove 'body='
            $body_content = $this->sanitizeBody($body_content);

            if (!empty($body_content)) {
                $uri->query = 'body=' . $body_content;
            } else {
                $uri->query = null;
            }
        }

        return true;
    }

    /**
     * Sanitizes SMS body content
     * @param string $body
     * @return string
     */
    private function sanitizeBody($body)
    {
        // Remove potentially dangerous characters
        $sanitized = preg_replace('/[<>"\']/', '', $body);
        // Remove any remaining script-like content
        $sanitized = preg_replace('/script|alert|javascript/i', '', $sanitized);
        return $sanitized;
    }
}
