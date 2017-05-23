PHP Session-Based Flash Messages
================================

Copyright 2012 Mike Everhart (http://mikeeverhart.net)

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.


Description
-----------

Stores messages in Session data to be easily retrieved later on. This class includes four different types of messages:
* Success
* Error
* Warning
* Information

Read more: http://mikeeverhart.net/php/session-based-flash-messages/

Basic Usage
-----------

````php
<?php

// Start a Session
if( !session_id() ) @session_start();
	
// Include and Instantiate the Class
require_once('class.messages.php');
$msg = new Messages();

// Now you can add messages
$msg->add('s', 'This is a success message!');
$msg->add('e', 'This is a error message!');
$msg->add('w', 'This is a Warning message!');
$msg->add('i', 'This is a Information message!');

// If you need to check for errors (ie: when validating a form) you can:
if( $msg->hasErrors() ) {
	// There ARE errors
} else {
    // There are NOT any error
}
	
// Where ever you want to display the messages simply call:
echo $msg->display();

?>
````

Update
------

Now you can pass a URL as a third parameter, and the user will get redirected immediately after the message is added:
````php
<?php $msg->add('e', 'An error has occurred.', 'http://website.com/page.php'); ?>
````
 
