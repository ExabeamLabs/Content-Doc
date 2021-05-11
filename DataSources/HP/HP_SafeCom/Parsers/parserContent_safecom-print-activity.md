#### Parser Content
```Java
{
Name = safecom-print-activity
  Vendor = HP
  Product = HP SafeCom
  Lms = Direct
  DataType = "print-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ JobName="""", """, JobDateTime="""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """\WPMComputerName="({host}[\w\-.]+)""",
    """\WDocComputerName="({host}[\w\-.]+)""",
    """\WJobDateTime="({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """\WJobName="({object}[^",]+)""",
    """\WDeviceName="({printer_name}[^",]+)""",
    """\WDeviceName="({activity}[^",]+)""",
    """\WUserLogon="({user}[^\s",]+)""",
    """\WUserFullName="({user}[^\s",]+)""",
    """\WUserEMail="({user_email}[^\s",]+)""",
    """\WJobSize="({bytes}\d{1,100})""",
    """\WTrackingPageCount="({num_pages}\d{1,100})"""
  ]
  DupFields = [ "host->dest_host" ]
}
```