#### Parser Content
```Java
{
Name = s-pharos-print-activity
  Vendor = Pharos
  Lms = Splunk
  DataType = "print-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """ JobName=""", """ UserName=""", """ DeviceName=""", """ Time_Printed=""",]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """(^|exabeam_\w+=)({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+)\s+(?!exabeam)""",
    """\sUserName=({user}.+?)(\s+\w+=|\s*$)""",
    """\sJobName="?({object}.+?)"?(\s+\w+=|\s*$)""",
    """\sPages=({num_pages}\d+)(\s+\w+=|\s*$)""",
    """\sFileSize=({bytes}\d+)(\s+\w+=|\s*$)""",
    """\sDeviceName=({printer_name}.+?)(\s+\w+=|\s*$)""",
    """\sDeviceName=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(\s+\w+=|\s*$)""",
    """\sApplicationName=(Unknown|({process_name}.+?))(\s+\w+=|\s*$)""",
  ]
}
```