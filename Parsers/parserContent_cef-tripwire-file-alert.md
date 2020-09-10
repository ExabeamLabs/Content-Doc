#### Parser Content
```Java
{
Name = cef-tripwire-file-alert
  Vendor = Tripwire Enterprise
  Lms = Splunk
  DataType = "file-alert"
  IsHVF = true
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """|Tripwire|Enterprise|""", "elementOIDLabel" ]
  Fields = [
    """\|rt=({time}\w+ \d+ \d\d\d\d \d\d:\d\d:\d\d)""",
    """\|dvchost=({host}[^|]+)\|""",
    """\|duser=(?:not available|(({domain}[^\\]+)\\)?({user}[^|]+))\|""",
    """\|Tripwire\|([^|]*\|){3}({alert_name}[^|]+)\|""",
    """\|cs2=({accesses}[^|]+)\|""",
    """\|cs3=({alert_type}[^|]+)\|""",
    """\|sproc=(?:not available|({process}[^|]+))\|""",
    """\|sproc=(?:not available|({directory}[^|]+)[\\\/]+[^\\\/]+)\|""",
    """\|sproc=(?:not available|([^|]+[\\\/]+)?({process_name}[^|]+))\|""",
    """\|fname=({file_path}[^|]+)\|""",
    """\|fname=({file_parent}[^|]+)[\\\/]+[^\\\/]+\|""",
    """\|fname=([^|]*[\\\/]+)?({file_name}[^\\\/|]+)\|""",
    """\|fname=[^|]+[\\\/]+[^\\\/|.]+\.({file_ext}[^\\\/|]+)\|""",
    """\|dhost=({dest_host}[^|]+)\|""",
    """\|cs1=({os}[^|]+) Server\|""",
    """\|cs6=(?:Unknown|({hash_type}[^|]+))\|""",
    """\|oldFileHash=(?:not available|({old_hash}[^|]+))\|""",
    """\|fileHash=(?:not available|({new_hash}[^|]+))\|"""
  ]
  DupFields = [ "directory->process_directory" ]
}
```