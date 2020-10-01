#### Parser Content
```Java
{
Name = hp-print-activity
  Vendor = HP SafeCom
  Product = HP SafeCom
  Lms = Syslog
  DataType = "print-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"run_id"""",""""print_size"""",""""userid"""", """"employee_cms_code"""", """"day_of_week"""" ]
  Fields = [
    """"date_part":"({time}\d+-\d+-\d+T\d+:\d+:\d+\.\d+Z)"""
    """exabeam_host=({host}[^\s]+)""",
    """"userid":"({user}[^"]+)""",
    """"printer_name":"({printer_name}.+?)\s*"""",
    """"pages_printed":({num_pages}\d+)""",
    """"document_details":"({object}.+?)\s*"""",
    """"employee_cms_code":"({user_id}\d+)""",
    """"print_size":({bytes}\d+)""",
  ]
  DupFields = ["printer_name->dest_host"]
}
```