# slim-download

This is an extension to the [SLIM framework](https://github.com/codeguy/Slim) vers.2 to implement the download of a file from a route.
It can be used to check the user permissions before of permits the downloading of a file, to count the number of download or for something else useful.

##Installation
Using composer you can add use this as your composer.json

```json
    {
        "require": {
            "simotod/slim-download": "dev-master"
        }
    }

```

##Usage
```php
    require 'vendor/autoload.php';

    $app = new \Slim\Slim(); 

	$app->get('/download', function () use ($app) {
		//Do some stuff here
		
		$filepath = "/path/to/file";
		
		$app->view(new \SimoTod\SlimDownload\DownloadView());
		$app->render($filepath);
	});
	
	$app->run();
	
```

###example method
all your requests will be returning a file output.
the usage will be `$app->render( (string)$FILE_PATH, (array)$DATA);`
Downladed file use the real name and 'application/octet-stream' as content type.
Content type can be overriden by $DATA["CONTENT_TYPE"].
File name can be overriden by $DATA["FILENAME"].


```php
	$app->get('/download', function () use ($app) {
		//Do some stuff here
		
		$filepath = "/path/to/pdf";
		$data = array();
		$data["CONTENT_TYPE"] = "application/pdf";
		$data["FILENAME"] = "sample.pdf";
		
		$app->view(new \SimoTod\SlimDownload\DownloadView());
		$app->render($filepath);
	});
	
```
