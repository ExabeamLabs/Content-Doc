#### Parser Content
```Java
{
Name = cef-tripwire-file-alert
  Vendor = Tripwire Enterprise
  Product = Tripwire Enterprise
  Lms = Splunk
  DataType = "file-alert"
  IsHVF = true
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """|Tripwire|Enterprise|""", "elementOIDLabel" ]
  Fields = [
    """\|rt=({time}\w+ \d{1,100} \d\d\d\d \d\d:\d\d:\d\d)""",
    """\|dvchost=({host}[^|]{1,2000})\|""",
    """\|duser=(?:not available|(({domain}[^\\]{1,2000})\\)?({user}[^|]{1,2000}))\|""",
    """\|Tripwire\|([^|]{0,2000}\|){3}({alert_name}[^|]{1,2000})\|""",
    """\|cs2=({accesses}[^|]{1,2000})\|""",
    """\|cs3=({alert_type}[^|]{1,2000})\|""",
    """\|sproc=(?:not available|({process}[^|]{1,2000}))\|""",
    """\|sproc=(?:not available|({directory}[^|]{1,2000})[\\\/]{1,2000}[^\\\/]{1,2000})\|""",
    """\|sproc=(?:not available|([^|]{1,2000}[\\\/]{1,2000})?({process_name}[^|]{1,2000}))\|""",
    """\|fname=({file_path}[^|]{1,2000})\|""",
    """\|fname=({file_parent}[^|]{1,2000})[\\\/]{1,2000}[^\\\/]{1,2000}\|""",
    """\|fname=([^|]{0,2000}[\\\/]{1,2000})?({file_name}[^\\\/|]{1,2000})\|""",
    """\|fname=[^|]{1,2000}[\\\/]{1,2000}[^\\\/|.]{1,2000}\.({file_ext}[^\\\/|]{1,2000})\|""",
    """\|dhost=({dest_host}[^|]{1,2000})\|""",
    """\|cs1=({os}[^|]{1,2000}) Server\|""",
    """\|cs6=(?:Unknown|({hash_type}[^|]{1,2000}))\|""",
    """\|oldFileHash=(?:not available|({old_hash}[^|]{1,2000}))\|""",
    """\|fileHash=(?:not available|({new_hash}[^|]{1,2000}))\|"""
  ]
  DupFields = [ "directory->process_directory" ]
}
```