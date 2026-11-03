<?php

namespace iMSCP\Composer;

use Composer\Composer;
use Composer\IO\IOInterface;
use Composer\Package\PackageInterface;

abstract class AbstractInstaller
{
    protected $locations = [];
    protected $composer;
    protected $package;
    protected $io;

    /**
     * Initializes base installer.
     *
     * @param PackageInterface $package
     * @param Composer $composer
     * @param IOInterface $io
     */
    public function __construct(
        PackageInterface $package = null,
        Composer $composer = null,
        IOInterface $io = null
    ) {
        $this->composer = $composer;
        $this->package = $package;
        $this->io = $io;
    }

    /**
     * Return the install path based on package type.
     *
     * The returned path is always relative to the project root directory and
     * can never point to the project root directory itself or outside of it.
     *
     * @param  PackageInterface $package
     * @param  string $installerType
     * @return string
     * @throws \InvalidArgumentException
     */
    public function getInstallPath(PackageInterface $package, $installerType = ''): string
    {
        $type = $package->getType();
        $prettyName = $package->getPrettyName();

        if (strpos($prettyName, '/') !== false) {
            list($vendor, $name) = explode('/', $prettyName, 2);
        } else {
            $vendor = '';
            $name = $prettyName;
        }

        $availableVars = $this->inflectPackageVars(compact('name', 'vendor', 'type'));
        $extra = $package->getExtra();
        if (isset($extra['installer-name']) && $extra['installer-name'] !== '') {
            if (! is_string($extra['installer-name'])) {
                throw new \InvalidArgumentException(sprintf(
                    'Invalid installer-name for the "%s" package.', $prettyName
                ));
            }

            $availableVars['name'] = $extra['installer-name'];
        }

        // Names are used as path segments: no directory separator, no
        // traversal sequence
        foreach (['name', 'vendor'] as $var) {
            if (($var === 'name' || $availableVars[$var] !== '')
                && ! $this->isValidPathSegment($availableVars[$var])
            ) {
                throw new \InvalidArgumentException(sprintf(
                    'Invalid %s "%s" for the "%s" package.', $var, $availableVars[$var], $prettyName
                ));
            }
        }

        $installPath = null;

        if ($this->composer && $this->composer->getPackage()) {
            $extra = $this->composer->getPackage()->getExtra();
            if (! empty($extra['installer-paths']) && is_array($extra['installer-paths'])) {
                $customPath = $this->mapCustomInstallPaths($extra['installer-paths'], $prettyName, $type, $vendor);
                if ($customPath !== null) {
                    $installPath = $this->templatePath($customPath, $availableVars);
                }
            }
        }

        if ($installPath === null) {
            $packageType = substr($type, strlen($installerType) + 1);
            $locations = $this->getLocations();

            if (! isset($locations[$packageType])) {
                throw new \InvalidArgumentException(sprintf('Package type "%s" is not supported', $type));
            }

            $installPath = $this->templatePath($locations[$packageType], $availableVars);
        }

        return $this->checkInstallPath($installPath, $prettyName);
    }

    /**
     * Whether the given string is a valid path segment
     *
     * @param  mixed $segment
     * @return bool
     */
    protected function isValidPathSegment($segment): bool
    {
        return is_string($segment)
            && preg_match('/^[A-Za-z0-9_.-]+$/D', $segment) === 1
            && strpos($segment, '..') === false
            && $segment !== '.';
    }

    /**
     * Check that the given install path is relative to (and below) the project
     * root directory
     *
     * @param  string $path
     * @param  string $prettyName
     * @return string
     * @throws \InvalidArgumentException
     */
    protected function checkInstallPath(string $path, string $prettyName): string
    {
        $segments = array_values(array_filter(
            explode('/', str_replace('\\', '/', $path)),
            function ($segment) {
                return $segment !== '' && $segment !== '.';
            }
        ));

        if ($path === ''
            || $path[0] === '/'
            || $path[0] === '\\'
            || preg_match('/^[A-Za-z]:/', $path)
            || strpos($path, "\0") !== false
            || empty($segments)
            || in_array('..', $segments, true)
        ) {
            throw new \InvalidArgumentException(sprintf(
                'Invalid install path "%s" for the "%s" package.', $path, $prettyName
            ));
        }

        return $path;
    }

    /**
     * For an installer to override to modify the vars per installer.
     *
     * @param  array $vars
     * @return array
     */
    public function inflectPackageVars(array $vars): array
    {
        return $vars;
    }

    /**
     * Search through a passed paths array for a custom install path.
     *
     * @param  array $paths
     * @param  string $name
     * @param  string $type
     * @param  string $vendor = NULL
     * @return string|null Custom install path, NULL if none matches
     */
    protected function mapCustomInstallPaths(array $paths, $name, $type, $vendor = null): ?string
    {
        foreach ($paths as $path => $names) {
            $names = (array)$names;
            if (in_array($name, $names, true)
                || in_array('type:' . $type, $names, true)
                || ($vendor !== null && $vendor !== '' && in_array('vendor:' . $vendor, $names, true))
            ) {
                return (string)$path;
            }
        }

        return null;
    }

    /**
     * Replace vars in a path
     *
     * @param  string $path
     * @param  array $vars
     * @return string
     */
    protected function templatePath($path, array $vars = []): string
    {
        if (strpos($path, '{') !== false) {
            extract($vars);
            preg_match_all('@\{\$([A-Za-z0-9_]*)\}@i', $path, $matches);

            if (! empty($matches[1])) {
                foreach ($matches[1] as $var) {
                    $path = str_replace('{$' . $var . '}', isset($$var) ? (string)$$var : '', $path);
                }
            }
        }

        return $path;
    }

    /**
     * Gets the installer's locations
     *
     * @return array
     */
    public function getLocations(): array
    {
        return $this->locations;
    }
}
