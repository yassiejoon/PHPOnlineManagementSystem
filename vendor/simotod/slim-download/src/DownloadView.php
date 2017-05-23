<?php
namespace SimoTod\SlimDownload;

class DownloadView extends \Slim\View 
{
    public function render($path, $data = []) 
    {
        $app = \Slim\Slim::getInstance();
        
		if(!file_exists($path))  {
			$app->notFound();
			return;
		}
		
        $contentType = $data["CONTENT_TYPE"] ? $data["CONTENT_TYPE"] : 'application/octet-stream';
        $filename = $data["FILENAME"] ? $data["FILENAME"] : basename($path);

        $app->response->setStatus(200);
        $app->response()->header('Content-Type', $contentType);
        $app->response()->header('Content-Transfer-Encoding', 'Binary');
        $app->response()->header('Content-disposition', 'attachment; filename="'.$filename.'"');
        $app->response()->header('Content-Length', filesize($path));
        $app->response()->header('Expires', '0');
        $app->response()->header('Cache-Control', 'must-revalidate, post-check=0, pre-check=0');
        $app->response()->header('Pragma', 'public');

        ob_clean();
        ob_start();
        readfile($path);
        $content = ob_get_clean();

        $app->response()->body($content);

        $app->stop();
    }
}