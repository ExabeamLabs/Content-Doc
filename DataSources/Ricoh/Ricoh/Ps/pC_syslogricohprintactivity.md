#### Parser Content
```Java
{
Name = syslog-ricoh-print-activity
  Vendor = Ricoh
  Product = Ricoh
  Lms = Direct
  DataType = "print-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """OPERATION_TYPE=3""", """USER_NAME=""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d)""",
    """({host}[\w\-.]{1,2000})\sUSER_NAME=""",
    """\WUSER_NAME=({user}[^,]{1,2000})(,|\s{0,100}$)""",
    """\WJOB_NAME=({object}[^,]{1,2000})(,|\s{0,100}$)""",
    """\WCLIENT_MACHINE=({src_host}[^,]{1,2000})(,|\s{0,100}$)""",
    """\WDATA_SIZE=({bytes}\d{1,100})""",
    """\WBEFORE_PAGES=({num_pages}\d{1,100})""",
    """\WSTORED_HOST=({printer_name}[^,]{1,2000})(,|\s{0,100}$)"""
  ]
}
```