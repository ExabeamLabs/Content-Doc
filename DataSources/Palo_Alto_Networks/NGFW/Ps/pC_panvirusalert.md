#### Parser Content
```Java
{
Name = pan-virus-alert
  Vendor = Palo Alto Networks
  Product = NGFW
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """,THREAT,virus,""" ]
  Fields = [
    """exabeam_host=({host}[^\s]{1,2000})""", 
    """"host":\{[^=]{0,2000}?"name":"({host}[^"]{1,2000})"[^=]{0,2000}?\}""",
    """,THREAT,([^,]{0,2000}.){55}({host}[^,]{1,2000}),""",
    """,THREAT(,[^,]{0,2000}){40

}
```