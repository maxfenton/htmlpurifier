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
 *
 * Whichever of the two forms the author wrote is preserved on output:
 * the generic RFC 3986 parser only recognises "?" as the query
 * delimiter, so a "&body=" ends up in the path and a "?body=" ends up
 * in the query, and each is re-emitted the way it came in. Any other
 * parameter (subject, etc.) is dropped.
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

        // Extract phone number and parameters from path and query
        $phone_number = $uri->path;
        $body_content = null;
        $body_in_path = false;

        // Non-standard but common: sms:number&body=message. The parser leaves
        // this entirely in the path, since "&" is not a query delimiter.
        if (strpos($phone_number, '&') !== false) {
            $parts = explode('&', $phone_number);
            $phone_number = array_shift($parts); // First part is the phone number
            $body_content = $this->extractBody($parts);
            $body_in_path = !is_null($body_content);
        }

        // Standard RFC 5724: sms:number?body=message. The query may hold several
        // parameters, e.g. "body=Hello&subject=Test". A query body wins over a
        // path one, so a mixed URI normalizes to the spec form.
        if (!is_null($uri->query)) {
            $query_body = $this->extractBody(explode('&', $uri->query));
            if (!is_null($query_body)) {
                $body_content = $query_body;
                $body_in_path = false;
            }
        }

        // Clean the phone number part
        $phone_number = preg_replace(
            '/(?!^\+)[^\d]/',
            '',
            rawurldecode($phone_number)
        );

        // Sanitize the body content if present
        if ($body_content !== null) {
            $body_content = $this->sanitizeBody($body_content);
        }

        // Re-emit the body in whichever form the author used, keeping an empty
        // body rather than dropping the parameter entirely.
        if (is_null($body_content)) {
            $uri->path = $phone_number;
            $uri->query = null;
        } elseif ($body_in_path) {
            $uri->path = $phone_number . '&body=' . $body_content;
            $uri->query = null;
        } else {
            $uri->path = $phone_number;
            $uri->query = 'body=' . $body_content;
        }

        return true;
    }

    /**
     * Returns the first 'body' value from a list of "name=value" pairs, or
     * null when there is none. Every other parameter is ignored/stripped.
     * @param string[] $params
     * @return string|null
     */
    private function extractBody($params)
    {
        foreach ($params as $param) {
            if (strpos($param, '=') === false) {
                continue;
            }
            list($param_name, $param_value) = explode('=', $param, 2);
            if ($param_name === 'body') {
                return $param_value;
            }
        }
        return null;
    }

    /**
     * Sanitizes SMS body content
     * @param string $body
     * @return string
     */
    private function sanitizeBody($body)
    {
        // Decode URL encoding first so encoded payloads are caught
        $decoded = rawurldecode($body);

        // Angle brackets are the primary HTML injection vector — reject the
        // entire body if they appear rather than trying to strip them partially
        if (strpos($decoded, '<') !== false || strpos($decoded, '>') !== false) {
            return '';
        }

        // Strip quote characters that could break HTML attribute context
        $sanitized = preg_replace('/[\'"]/', '', $decoded);

        // Re-encode so the value is safe for embedding in a URL attribute
        return rawurlencode($sanitized);
    }
}
