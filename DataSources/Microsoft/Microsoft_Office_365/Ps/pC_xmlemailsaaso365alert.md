#### Parser Content
```Java
{
Name = xml-email-saas-o365-alert
  Vendor = Microsoft
  Product = Microsoft Office 365
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSS"
  Conditions = [ """office365""", """<d:FromIP""", """<d:Organization""", """<d:Subject""", "MessageTrace" ]
  Fields = [
    """<d:Received.+?>({time}.+?)<\/d:Received>""",
    """<d:SenderAddress>({sender}.+?)<\/d:SenderAddress>""",
    """<d:RecipientAddress>({recipient}.+?)<\/d:RecipientAddress>""",
    """<d:Subject>({subject}.+?)<\/d:Subject>""",
    """<d:Organization>({domain}.+?)<\/d:Organization>""",
    """<d:StartDate.+?>({time_started}.+?)<\/d:StartDate>""",
    """<d:EndDate.+?>({time_ended}.+?)<\/d:EndDate>""",
    """<d:FromIP>({src_ip}.+?)<\/d:FromIP>""",
    """<d:Size.+?>({bytes}.+?)<\/d:Size>""",
    """<d:Status>({outcome}.+?)<\/d:Status>""",
  ]
  DupFields = [ "subject->alert_name" ]


}
```