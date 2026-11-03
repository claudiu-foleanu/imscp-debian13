# [Composer](https://getcomposer.org) installers for [i-MSCP](https://www.i-mscp.net/)

[![Build Status](https://secure.travis-ci.org/i-MSCP/composer-installers.svg?branch=master)](https://secure.travis-ci.org/i-MSCP/composer-installers)
[![Coverage Status](https://coveralls.io/repos/github/i-MSCP/composer-installers/badge.svg?branch=master&service=github)](https://coveralls.io/github/i-MSCP/composer-installers?branch=master)

This is for i-MSCP composer package authors to require in their `composer.json`.
It will install their package to the correct location based on the specified
package type.

## Current supported installers and package types

| Installer | Types
| --------- | -----
| i-MSCP    | <b>`imscp-plugin`</b><br><b>`imscp-theme`</b><br><b>`imscp-tool`</b>
| Roundcube | <b>`roundcube-plugin`</b>
## Example `composer.json`

This is an example for the i-MSCP PhpMyAdmin composer package. The only
important parts to set in the composer.json file are `"type": "imscp-tool"`
which describes what package is and `"require": { "imscp/composer-installers": "^1.0" }`
which tells composer to load the custom installers.

```json
{
    "name": "imscp/phpmyadmin",
    "type": "imscp-tool",
    "require": {
        "imscp/composer-installers": "^1.0"
    }
}
```

This would install the package to the `gui/public/tools/phpmyadmin/` path.

## Custom install paths

i-MSCP developers and/or administrators can override the install paths in
different ways, using the `installer-paths` extra in the `composer.json` of the
i-MSCP instance :
 
### Per package basis

```json
{
    "extra": {
        "installer-paths": {
            "custom/path/{$name}/": [
                "konzeptplus/imscp-api",
                "imscp/dns-provisioning"
            ]
        }
    }
}
```

would install both the `konzeptplus/imscp-api` and `imscp/dns-provisioning`
packages into the `custom/path/{$name}/` path.

### Per package type basis

``` json
{
    "extra": {
        "installer-paths": {
            "custom/path/{$name}/": [
                 "type:imscp-plugin"
             ]
        }
    }
}
```

would install any package of type `imscp-plugin` into the
`custom/path/{$name}/` path.

### Per vendor basis

``` json
{
    "extra": {
        "installer-paths": {
            "custom/path/{$name}/": [
                "vendor:konzeptplus"
            ]
        }
    }
}
```

would install any package provided by the `konzeptplus` vendor into the
`custom/path/{$name}/` path.

In all the above cases, the following variables are available for use in paths:

- `{$name}`: Package name
- `{$vendor}` Vendor name
- `{$type}` Package type

## Custom install name

As a package author, you can name it differently when installed by using the
`installer-name` extra in the package `composer.json`. 

If you have a package named `imscp/roundcube` of type` imscp-tool`, it would
be installed in the `gui/public/tools/roundcube` path. To provide this
package as default Webmail, you need override its name as follows:

```json
{
    "name": "imscp/roundcube",
    "type": "imscp-tool",
    "extra": {
        "installer-name": "webmail"
    }
}
```

By doing so, the package would be installed in the `gui/public/tools/webmail`
path.

## Disabling installers

There may be time when you want to disable one or more installers from
`imscp/composer-installers`. For instance, if you are managing a package  that
uses a specific installer that conflicts with `imscp/composer-installers` but
also have a dependency on a package that depends on `imscp/composer-installers`.

Installers can be disabled by specifying the extra `installer-disable`
property. If set to `true`, `"all"`, or `"*"` all installers will be disabled. 

```json
{
    "extra": {
        "installer-disable": true
    }
}
```

Otherwise a single installer or an array of installers may be specified.

```json
{
    "extra": {
        "installer-disable": [
            "imscp",
            "roundcube"
        ]
    }
}
```

**Note:** Using a global disable value (`true`, `"all"`, or `"*"`) will take
precedence over individual installer names if used in an array. The example
below will disable all installers.

```json
{
    "extra": {
        "installer-disable": [
          "imscp",
          "all"
        ]
    }
}
```
