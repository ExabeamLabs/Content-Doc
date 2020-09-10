#### Parser Content
```Java
{
Name = syslog-ricoh-print-activity
  Vendor = Ricoh
  Lms = Direct
  DataType = "print-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """OPERATION_TYPE=3""", """USER_NAME=""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d)""",
    """({host}[\w\-.]+)\sUSER_NAME=""",
    """\WUSER_NAME=({user}[^,]+)(,|\s*$)""",
    """\WJOB_NAME=({object}[^,]+)(,|\s*$)""",
    """\WCLIENT_MACHINE=({src_host}[^,]+)(,|\s*$)""",
    """\WDATA_SIZE=({bytes}\d+)""",
    """\WBEFORE_PAGES=({num_pages}\d+)""",
    """\WSTORED_HOST=({printer_name}[^,]+)(,|\s*$)"""
  ]
}
```