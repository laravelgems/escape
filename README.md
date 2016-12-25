# Make your pages safer

[![Build Status](https://travis-ci.org/laravelgems/escape.svg?branch=master)](https://travis-ci.org/laravelgems/escape)

This library provides several methods that help you prevent XSS attacks on your pages.

These methods escape untrusted data properly. Just follow simple rules and you're safe.

## Quick example
```php
<div>
    <label><?= \LaravelGems\HTML::text($label) ?></label>
    <input type="text" value="<?= \LaravelGems\HTML::attr($value) ?>"/>
    <script>
        var Identifier = "<?= \LaravelGems\HTML::js($label) ?>";
    </script>
</div>
<a href="/my/page?query=<?= \LaravelGems\HTML::param($label) ?>" onclick="callMyFunction(this, '<?= \LaravelGems\HTML::js($label) ?>');">Click Me</a>
```

## Important:
- this library **does not** do any validation
- this library **does not** clean invalid/dangerous code

So, please do not expect that this library will protect you from something like this:
```php
<a href="#" onclick="UNTRUSTED DATA HERE">My Link</a>
<a href="UNTRUSTED DATA HERE">My Link</a>
```

## Installation
Include `HTML.php` or install [the composer package](https://packagist.org/packages/laravelgems/escape)
```shell
composer require laravelgems/escape 
```
 
## HTML text
This methods uses `htmlspecialchars` with small addition (escaping forward slash too).
```php
<div><?= \LaravelGems\HTML::text($untrustedData) ?></div>
```

## HTML attribute
```php
<input type="text" name="username" value="<?= \LaravelGems\HTML::attr($untrustedData) ?>"/>
```
#### Important - this is only safe for whitelist of attributes
Whitelist: align, alink, alt, bgcolor, border, cellpadding, cellspacing, class, color, cols, colspan, coords, dir, face, height, hspace, ismap, lang, marginheight, marginwidth, multiple, nohref, noresize, noshade, nowrap, ref, rel, rev, rows, rowspan, scrolling, shape, span, summary, tabindex, title, usemap, valign, value, vlink, vspace, width

Some attributes (for example, `ID`) is not in a whitelist as it can be used for breaking your frontend logic by processing/watching wrong element.

Many **other attributes are potentially dangerous** even with properly escaped data.

## CSS
```php
<span style="property: '<?= \LaravelGems\HTML::css($untrustedData) ?>;'">text</span>
```
Notes: 
- value should be quoted
- stay away from putting untrusted data into complex properties like url, behavior, and custom (-moz-binding)
- do not put untrusted data into IE’s expression property value which allows JavaScript.

## Javascript variable
```php
<script>var username="<?= \LaravelGems\HTML::js($untrustedData) ?>";</script>
<a href="#" onclick="myClickHandler('<?= \LaravelGems\HTML::js($untrustedData) ?>')">Link</a>
```

## URL parameter
FYI, this method is an alias to `urlencode`.
```php
<a href="/profile?username=<?= \LaravelGems\HTML::param($untrustedData) ?>">Profile</a>
```

## Warning! Never ever make something like these without validation/sanitizing
```php
<!-- Unsafe html attributes - there no way to protect you in 100% cases without validation first -->
<embed src="<?= htmlentities("javascript:alert(1)") ?>"></embed>

<!-- Does not look safe, right? -->
<embed src="javascript:alert(1)"></embed>
```

## More examples (wrong vs right)
```php
<!-- WRONG WAY: htmlentities() is not enough in JS context -->
<script>var a = "<?= htmlentities($untrustedData) ?>";</script>

<!-- RIGHT WAY: use \LaravelGems\HTML::js() -->
<script>var a = "<?= \LaravelGems\HTML::js($untrustedData) ?>";</script>
```

## Inspiration
Thanks to QWASP for their top 10 and cheat sheets. Thanks to Twig library for their filters.

