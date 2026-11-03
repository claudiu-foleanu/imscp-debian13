<?php

namespace iMSCP\Composer;

use Composer\Composer;
use Composer\IO\IOInterface;
use Composer\Plugin\PluginInterface;

class Plugin implements PluginInterface
{
    /**
     * @var Installer
     */
    private $installer;

    public function activate(Composer $composer, IOInterface $io)
    {
        $this->installer = new Installer($io, $composer);
        $composer->getInstallationManager()->addInstaller($this->installer);
    }

    /**
     * Composer 2.x plugin API
     */
    public function deactivate(Composer $composer, IOInterface $io)
    {
        if ($this->installer !== null) {
            $composer->getInstallationManager()->removeInstaller($this->installer);
        }
    }

    /**
     * Composer 2.x plugin API
     */
    public function uninstall(Composer $composer, IOInterface $io)
    {
    }
}
