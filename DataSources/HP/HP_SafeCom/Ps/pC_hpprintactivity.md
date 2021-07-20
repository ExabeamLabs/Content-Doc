#### Parser Content
```Java
{
Name = hp-print-activity
  Vendor = HP
  Product = HP SafeCom
  Lms = Syslog
  DataType = "print-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"run_id"""",""""print_size"""",""""userid"""", """"employee_cms_code"""", """"day_of_week"""" ]
  Fields = [
    """"date_part":"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}Z)"""
    """exabeam_host=({host}[^\s]{1,2000})""",
    """"userid":"({user}[^"]{1,2000})""",
    """"printer_name":"({printer_name}.+?)\s{0,100}"""",
    """"pages_printed":({num_pages}\d{1,100})""",
    """"document_details":"({object}.+?)\s{0,100}"""",
    """"employee_cms_code":"({user_id}\d{1,100})""",
    """"print_size":({bytes}\d{1,100})""",
  ]
  DupFields = ["printer_name->dest_host"]
}
```