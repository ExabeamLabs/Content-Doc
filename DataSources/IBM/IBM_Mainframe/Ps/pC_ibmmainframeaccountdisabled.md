#### Parser Content
```Java
{
Name = ibm-mainframe-account-disabled
   DataType = "account-disabled"
   Conditions = [ """"MFSOURCETYPE":"SYSLOG"""", """"MSGTXT":"""", """ was suspended on """ ]
   Fields = ${AAIBMParserTemplates.ibm-mainframe-events.Fields}[
     """({event_name}suspended)""",
     """"MSGTXT":"[^"]{1,2000}?\sUserID ({user}[^"\s]{1,2000})\sfor"""
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