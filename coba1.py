import time
import io

def follow(thefile):
    """
    Generator function that yields new lines in a file
    as they are written, simulating 'tail -f'.
    """
    # Seek to the end of the file
    thefile.seek(0, io.SEEK_END)
    
    while True:
        line = thefile.readline()
        if not line:
            # Sleep briefly to avoid a busy loop when no new lines are available
            time.sleep(0.1)
            continue
        yield line

if __name__ == '__main__':
    log_file_path = '/var/log/mikrotik1.log' # Replace with your log file path

    # Open the file in read mode ('r')
    with open(log_file_path, "r") as log_file:
        # Create the generator
        loglines = follow(log_file)
        # Iterate over the generator to process new lines as they arrive
        for line in loglines:
            print(line.strip()) # strip() to remove trailing newlines
