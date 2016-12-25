<?php

use LaravelGems\Escape\HTML;

/**
 * Class HTMLTest
 */
class HTMLTest extends \PHPUnit_Framework_TestCase
{
    /**
     * Tests LaravelGems\Escape\HTML::css
     *
     * @dataProvider provideCss
     */
    public function testEscapeCss($untrusted, $expected)
    {
        $this->assertEquals($expected, HTML::css($untrusted));
    }

    /**
     * Tests LaravelGems\Escape\HTML::text
     *
     * @dataProvider provideText
     */
    public function testEscapeText($untrusted, $expected)
    {
        $this->assertEquals($expected, HTML::text($untrusted));
    }

    /**
     * Tests LaravelGems\Escape\HTML::attr
     *
     * @dataProvider provideAttr
     */
    public function testEscapeAttr($untrusted, $expected)
    {
        $this->assertEquals($expected, HTML::attr($untrusted));
    }


    /**
     * Tests LaravelGems\Escape\HTML::js
     *
     * @dataProvider provideJavascriptValue
     */
    public function testEscapeJavascriptValue($untrusted, $expected)
    {
        $this->assertEquals($expected, HTML::js($untrusted));
    }

    /**
     * Tests LaravelGems\BladeEscapers\Classes\HTML::urlParam
     *
     * @dataProvider provideUrlParam
     */
    public function testEscapeUrlParam($untrusted, $expected)
    {
        $this->assertEquals($expected, HTML::param($untrusted));
    }

    /**
     * Provides test cases for testEscapeCss
     */
    public function provideCss()
    {
        return array(
            // alphanum - as is
            array("ff00ff", "ff00ff"),

            // special characters
            array(";\"'&<>", "\\3B \\22 \\27 \\26 \\3C \\3E "),

            // japaneses hello world
            array("こんにちは世界", "\\3053 \\3093 \\306B \\3061 \\306F \\4E16 \\754C "),

            // russian hello world
            array("Привет Мир", "\\41F \\440 \\438 \\432 \\435 \\442 \\20 \\41C \\438 \\440 "),

            // \0
            array("test\0oops", "test\\0 oops")
        );
    }

    /**
     * Provides test cases for testEscapeText
     */
    public function provideText()
    {
        return array(
            // just empty string
            array('', ''),

            // no entities
            array('test', 'test'),

            // entities
            array('&', '&amp;'),
            array('<', '&lt;'),
            array('>', '&gt;'),
            array('"', '&quot;'),
            array("'", '&#039;'), // aka &#x27
            array('/', '&#x2F;'),

            // double escaping
            array('&amp;', '&amp;amp;'),

            // some example
            array("<script>alert('xss')</script>", "&lt;script&gt;alert(&#039;xss&#039;)&lt;&#x2F;script&gt;")
        );
    }

    /**
     * Provides test cases for testEscapeAttr
     */
    public function provideAttr()
    {
        return array(
            // alphanum - as is
            array('hello123', 'hello123'),

            // entities - "(quote), &(amp), <(less-than), >(greater-than)
            array('"&<>', '&quot;&amp;&lt;&gt;'),

            // some special characters - \ / ; ' `( ) []
            array('\\/;\'`()[]', '&#x5C;&#x2F;&#x3B;&#x27;&#x60;&#x28;&#x29;&#x5B;&#x5D;'),

            // japanese hello world
            array('こんにちは世界', '&#x3053;&#x3093;&#x306B;&#x3061;&#x306F;&#x4E16;&#x754C;'),

            // russian Hello world
            array('Привет Мир', '&#x041F;&#x0440;&#x0438;&#x0432;&#x0435;&#x0442;&#x20;&#x041C;&#x0438;&#x0440;'),

            // undefined entity
            array("test" . chr(5) . "test", 'test&#xFFFD;test'),
        );
    }

    /**
     * Provides test cases for testEscapeJavascriptValue
     */
    public function provideJavascriptValue()
    {
        return array(
            // alphanum - as is
            array('hello123', 'hello123'),

            // entities - "(quote), &(amp), <(less-than), >(greater-than)
            array('"&<>', '\\x22\\x26\\x3C\\x3E'),

            // some special characters - \ / ; ' `( ) []
            array('\\/;\'`()[]', '\\x5C\\x2F\\x3B\\x27\\x60\\x28\\x29\\x5B\\x5D'),

            // japanese hello world
            array('こんにちは世界', '\\u3053\\u3093\\u306B\\u3061\\u306F\\u4E16\\u754C'),

            // russian Hello world
            array('Привет Мир', '\\u041F\\u0440\\u0438\\u0432\\u0435\\u0442\\x20\\u041C\\u0438\\u0440'),
        );
    }

    /**
     * Provides test cases for testEscapeUrlParam
     */
    public function provideUrlParam()
    {
        return array(
            // alphanum - as is
            array('hello123', 'hello123'),

            // entities - "(quote), &(amp), <(less-than), >(greater-than)
            array('"&<>', '%22%26%3C%3E'),

            // some special characters - \ / ; ' `( ) []
            array('\\/;\'`()[]', '%5C%2F%3B%27%60%28%29%5B%5D'),

            // japanese hello world
            array('こんにちは世界', '%E3%81%93%E3%82%93%E3%81%AB%E3%81%A1%E3%81%AF%E4%B8%96%E7%95%8C'),

            // russian Hello world
            array('Привет Мир', '%D0%9F%D1%80%D0%B8%D0%B2%D0%B5%D1%82+%D0%9C%D0%B8%D1%80'),
        );
    }
}
