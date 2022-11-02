#### Parser Content
```Java
{
Name = ibm-mainframe-app-login
   DataType = "app-login"
   Conditions = [ """"MFSOURCETYPE":"SYSLOG"""", """"MSGTXT":"""", """ LOGGED ON """ ]
   Fields = ${AAIBMParserTemplates.ibm-mainframe-events.Fields}[
     """({event_name}LOGGED ON)""",
     """"MSGTXT":"[^"\s]{1,2000}?\s({user}[^"\s]{1,2000})\s\S{1,2000}?\sLOGGED ON"""
   ]

ibm-mainframe-events {
    Vendor = IBM
    Product = IBM Mainframe
    Lms = Direct
    TimeFormat = "yyyy-MM-dd HH:mm:ss.SS Z"
    Fields = [ 
      """"DATETIME":"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d{2}\s(\+|\-)\d{4}?)"""",
      """"ACTION":"({severity}[^"]{1,2000}?)"""", 
      """"MSGNUM":"({event_code}[^"]{1,2000}?)"""",
      """"MSGTXT":"({additional_info}[^"]{1,2000}?)"""" 
    
}
```