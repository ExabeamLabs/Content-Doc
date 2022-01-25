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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\WPMComputerName="({host}[\w\-.]{1,2000})""",
    """\WDocComputerName="({host}[\w\-.]{1,2000})""",
    """\WJobDateTime="({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """\WJobName="({object}[^",]{1,2000})""",
    """\WDeviceName="({printer_name}[^",]{1,2000})""",
    """\WDeviceName="({activity}[^",]{1,2000})""",
    """\WUserLogon="({user}[^\s",]{1,2000})""",
    """\WUserFullName="({user}[^\s",]{1,2000})""",
    """\WUserEMail="({user_email}[^\s",]{1,2000})""",
    """\WJobSize="({bytes}\d{1,100})""",
    """\WTrackingPageCount="({num_pages}\d{1,100})"""
  ]
  DupFields = [ "host->dest_host" ]
}
```