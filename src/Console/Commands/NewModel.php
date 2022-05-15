<?php

use Melonly\Console\Command;
use Melonly\Filesystem\File;

return new class extends Command {
    public function __construct() {
        parent::__construct();
    }

    public function handle(): void {
        $fileName = __DIR__ . '/../../../../../../src/Models/' . $this->arguments[2] . '.php';

        if (File::exists($fileName)) {
            $this->errorLine("Model '{$this->arguments[2]}' already exists");

            return;
        }

        $this->publishFileFromTemplate($fileName, 'model', [
            'class' => $this->arguments[2],
        ]);

        $this->infoLine("Created model '{$this->arguments[2]}'");
    }
};
