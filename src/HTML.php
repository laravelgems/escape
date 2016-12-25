<?php

namespace LaravelGems\Escape;

/**
 * Class Escape provides different methods to escape untrusted data
 *
 * Follows recommendations:
 * @see https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet#XSS_Prevention_Rules_Summary
 */
class HTML
{
    /**
     * Escapes untrusted data for inserting into a property value
     *
     *  <style>selector { property : ...ESCAPE UNTRUSTED DATA BEFORE PUTTING HERE...; } </style>
     *  <style>selector { property : "...ESCAPE UNTRUSTED DATA BEFORE PUTTING HERE..."; } </style>
     *  <span style="property : ...ESCAPE UNTRUSTED DATA BEFORE PUTTING HERE...">text</span>
     *
     * Per QWASP:
     * It's important that you only use untrusted data in a property value and not into other places in style data.
     * You should stay away from putting untrusted data into complex properties like url, behavior, and custom (-moz-binding).
     * You should also not put untrusted data into IE’s expression property value which allows JavaScript.
     * Please note there are some CSS contexts that can never safely use untrusted data as input - EVEN IF PROPERLY CSS ESCAPED!
     * You will have to ensure that URLs only start with "http" not "javascript" and that properties never start with "expression".
     *
     * @param string $string Untrusted data
     *
     * @return string Escaped data for inserting into a property value
     */
    public static function css($string)
    {
        $string = preg_replace_callback('#[^a-zA-Z0-9]#Su', function ($matches) {
            $char = $matches[0];
            // \xHH
            if (!isset($char[1])) {
                $hex = ltrim(strtoupper(bin2hex($char)), '0');
                if (0 === strlen($hex)) {
                    $hex = '0';
                }
                // Using a two character escape can cause problems if the next character continues the escape sequence.
                // There is a solution - add a space after the CSS escape (will be ignored by the CSS parser)
                return '\\' . $hex . ' ';
            }
            // \uHHHH
            $char = iconv('UTF-8', 'UTF-16BE', $char);
            return '\\' . ltrim(strtoupper(bin2hex($char)), '0') . ' ';
        }, $string);

        return $string;
    }

    /**
     * Escapes untrusted data for inserting into html body
     *
     * <body>...ESCAPE UNTRUSTED DATA BEFORE PUTTING HERE...</body>
     * <div>...ESCAPE UNTRUSTED DATA BEFORE PUTTING HERE...</div>
     *
     * Per QWASP:
     * Most web frameworks have a method for HTML escaping for the characters detailed below.
     * However, this is absolutely not sufficient for other HTML contexts (attribute, javascript and css)
     *
     * @param string $string Untrusted data
     *
     * @return string Escaped string
     */
    public static function text($string)
    {
        /**
         * HTML Entity Encoding
         *
         * & => &amp;
         * < => &lt;
         * > => &gt;
         * " => &quot;
         * ' => &#x27; aka &#039;
         */
        $escaped = htmlspecialchars($string, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

        /**
         * QWASP recommendation:
         * / => &#x2F;
         *
         * Forward slash is included as it helps end an HTML entity
         */
        $escaped = str_replace("/", "&#x2F;", $escaped);

        return $escaped;
    }

    /**
     * Escapes untrusted data for inserting into safe HTML Attribute
     *
     * <div attr='...ESCAPE UNTRUSTED DATA BEFORE PUTTING HERE...'>content</div>   inside single quoted attribute
     * <div attr="...ESCAPE UNTRUSTED DATA BEFORE PUTTING HERE...">content</div>   inside double quoted attribute
     *
     * Per QWASP:
     * Except for alphanumeric characters,
     * escape all characters with ASCII values less than 256 with the &#xHH; format (or a named entity if available)
     * to prevent switching out of the attribute. The reason this rule is so broad is that developers frequently
     * leave attributes unquoted. Properly quoted attributes can only be escaped with the corresponding quote.
     * Unquoted attributes can be broken out of with many characters, including [space] % * + , - / ; < = > ^ and |.
     *
     * Warning: Only place untrusted data into a whitelist of safe attributes
     *
     * Safe HTML Attributes include:
     *  align, alink, alt, bgcolor, border, cellpadding, cellspacing, class, color, cols, colspan, coords, dir,
     *  face, height, hspace, ismap, lang, marginheight, marginwidth, multiple, nohref, noresize, noshade, nowrap,
     *  ref, rel, rev, rows, rowspan, scrolling, shape, span, summary, tabindex, title, usemap,
     *  valign, value, vlink, vspace, width
     *
     * FYI, example with unsafe attribute (vulnerable in Firefox v50.1, 2016-12-23):
     * $value = 'javascript:alert(1)';
     * <embed src="{{$value}}"></embed>             => <embed src="javascript:alert(1)"></embed>
     * <embed src="@escapeattr($value)"></embed>    => <embed src="javascript&#x3A;alert&#x28;1&#x29;"></embed>
     *
     * @param string $string Untrusted data
     *
     * @return string Escaped data for inserting into a safe HTML attribute
     */
    public static function attr($string)
    {
        $string = preg_replace_callback('#[^a-zA-Z0-9,\.\-_]#Su', function ($matches) {
            /**
             * This function is adapted from code coming from Zend Framework.
             *
             * @copyright Copyright (c) 2005-2012 Zend Technologies USA Inc. (http://www.zend.com)
             * @license   http://framework.zend.com/license/new-bsd New BSD License
             */
            /*
             * While HTML supports far more named entities, the lowest common denominator
             * has become HTML5's XML Serialisation which is restricted to the those named
             * entities that XML supports. Using HTML entities would result in this error:
             *     XML Parsing Error: undefined entity
             */
            static $entityMap = array(
                34 => 'quot', /* quotation mark */
                38 => 'amp',  /* ampersand */
                60 => 'lt',   /* less-than sign */
                62 => 'gt',   /* greater-than sign */
            );
            $chr = $matches[0];
            $ord = ord($chr);
            /*
             * The following replaces characters undefined in HTML with the
             * hex entity for the Unicode replacement character.
             */
            if (($ord <= 0x1f && $chr != "\t" && $chr != "\n" && $chr != "\r") || ($ord >= 0x7f && $ord <= 0x9f)) {
                return '&#xFFFD;';
            }
            /*
             * Check if the current character to escape has a name entity we should
             * replace it with while grabbing the hex value of the character.
             */
            if (strlen($chr) == 1) {
                $hex = strtoupper(substr('00'.bin2hex($chr), -2));
            } else {
                $chr = iconv('UTF-8', 'UTF-16BE', $chr);
                $hex = strtoupper(substr('0000'.bin2hex($chr), -4));
            }
            $int = hexdec($hex);
            if (array_key_exists($int, $entityMap)) {
                return sprintf('&%s;', $entityMap[$int]);
            }
            /*
             * Per OWASP recommendations, we'll use hex entities for any other
             * characters where a named entity does not exist.
             */
            return sprintf('&#x%s;', $hex);
        }, $string);

        return $string;
    }

    /**
     * Escapes untrusted data for inserting into javascript variable, function parameter
     *
     * <script>var currentValue='UNTRUSTED DATA';</script>
     * <script>someFunction('UNTRUSTED DATA');</script>
     *
     * Per QWASP:
     * The only safe place to put untrusted data into this code is inside a quoted "data value".
     * Including untrusted data inside any other JavaScript context is quite dangerous,
     * as it is extremely easy to switch into an execution context with characters including (but not limited to)
     * semi-colon, equals, space, plus, and many more, so use with caution.
     *
     * Please note there are some JavaScript functions
     * that can never safely use untrusted data as input - EVEN IF JAVASCRIPT ESCAPED!
     *
     * <script>
     * window.setInterval('...EVEN IF YOU ESCAPE UNTRUSTED DATA YOU ARE XSSED HERE...');
     * </script>
     *
     * Except for alphanumeric characters, escape all characters with the \uXXXX unicode escaping format (X = Integer).
     *
     * @param string $string Untrusted data
     *
     * @return string Escaped data
     */
    public static function js($string)
    {
        // escape all non-alphanumeric characters
        // into their \xHH or \uHHHH representations
        $string = preg_replace_callback('#[^a-zA-Z0-9,\._]#Su', function ($matches) {
            $char = $matches[0];
            // \xHH
            if (!isset($char[1])) {
                return '\\x' . strtoupper(substr('00' . bin2hex($char), -2));
            }
            // \uHHHH
            $char = iconv('UTF-8', 'UTF-16BE', $char);
            return '\\u' . strtoupper(substr('0000'.bin2hex($char), -4));
        }, $string);

        return $string;
    }

    /**
     * Escape untrusted data for inserting as a get parameter
     *
     * <a href="/cool/site/search?value=UNTRUSTED DATA">click me</a>
     *
     * WARNING: Do not encode complete or relative URL's with URL encoding!
     * If untrusted input is meant to be placed into href, src or other URL-based attributes,
     * it should be validated to make sure it does not point to an unexpected protocol, especially Javascript links.
     * URL's should then be encoded based on the context of display like any other piece of data.
     * For example, user driven URL's in HREF links should be attribute encoded.
     *
     * Defense:
     *  URL Encoding
     *
     * @param string $value Untrusted data
     *
     * @return string Escaped (urlencoded) data
     */
    public static function param($value)
    {
        return urlencode($value);
    }
}