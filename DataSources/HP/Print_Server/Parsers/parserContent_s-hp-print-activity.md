#### Parser Content
```Java
{
Name = s-hp-print-activity
  Vendor = HP
  Product = Print Server
  Lms = Splunk
  DataType = "print-activity"
  TimeFormat =  "yyyy-MM-dd HH:mm:ss.S"
  Conditions = [ """PRINTER_lab_LocalName="""", """PRINTER_lab_Type="""", """PRINTER_lab_SerialNumber="""" ]
  Fields = [
    """JOB_date_Submitted="({time}\d{1,100}-\d{1,100}-\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100})""",
    """MPS_lab_Name="({host}[^"]{1,2000})""",
    """PRINTER_lab_LocalName="(Unspecified|({printer_name}[^"]{1,2000}))""",
    """PRINTER_lab_SerialNumber="(Unspecified|({printer_sn}[^"]{1,2000}))""",
    """JOB_lab_NTUserName="(Unspecified|({user}[^"]{1,2000}))""",
    """Lab_NTFullUserName="({user_lastname}[^",]{1,2000}),\s{0,100}({user_firstname}[^",]{1,2000})""",
    """JOB_lab_NTUserMachine="(Unspecified|({src_host}[^"]{1,2000}))""",
    """JOB_qty_PrintedPages="({num_pages}\d{1,100})""",
    """JOB_lab_DocumentName="(Unspecified|[\s-]{0,2000}({object}[^"]{1,2000}?))\s{0,100}"""",
    """PRINTER_lab_Type="(Unspecified|({activity}[^"]{1,2000}))""",
  ]
}
```