#### Parser Content
```Java
{
Name = ibm-mainframe-failed-app-login-2
   DataType = "failed-app-login"
   Conditions = [ """"MFSOURCETYPE":"SYSLOG"""", """"MSGTXT":"""", """PASSWORD MISSING""" ]
   Fields = ${AAIBMParserTemplates.ibm-mainframe-events.Fields}[
     """"MSGTXT":"[^"]{1,2000}?\sF=({failure_reason}[^"=]{1,2000}?)(\w+?=|")""",
     """"MSGTXT":"[^"]{1,2000}?\sA=({user}[^"\s=]{1,2000}?)\sT="""
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