#### Parser Content
```Java
{
Name = s-kaspersky-endpoint-security
  Vendor = Kaspersky
  Product = Kaspersky Endpoint Security for Business
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "YYYY-MM-DD HH:mm:ssZ"
  Conditions = [ """Kaspersky Endpoint Security 10 for Windows""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """Result:\s{0,100}({outcome}[^:]{1,2000})""",
    """<Row>(<Cell ss:StyleID="TableData"><Data ss:Type=[^\<]{1,2000}?>(<\/Cell>|[^\<]{1,2000}?<\/Data><\/Cell>)){5}<Cell ss:StyleID="TableData"><Data ss:Type=[^\<]{1,2000}?>(({file_parent}[^\<]{1,2000}?)\\+)?({file_name}[^\<\\]{1,2000}?(\.({file_ext}[^\<\.\s]{1,2000})))<\/Data><\/Cell>""", 
    """<Row>(<Cell ss:StyleID="TableData"><Data ss:Type=[^\<]{1,2000}?>(<\/Cell>|[^\<]{1,2000}?<\/Data><\/Cell>)){8}<Cell ss:StyleID="TableData"><Data ss:Type=[^\<]{1,2000}?>(({domain}[^\<]{1,2000})\\+)?({user}[^\<]{1,2000})<\/Data><\/Cell>""",
    """<Row>(<Cell ss:StyleID="TableData"><Data ss:Type=[^\<]{1,2000}?>(<\/Cell>|[^\<]{1,2000}?<\/Data><\/Cell>)){1}<Cell ss:StyleID="TableData"><Data ss:Type=[^\<]{1,2000}?>({group}[^\<]{1,2000}?)<\/Data><\/Cell>""",
    """<Row>(<Cell ss:StyleID="TableData"><Data ss:Type=[^\<]{1,2000}?>(<\/Cell>|[^\<]{1,2000}?<\/Data><\/Cell>)){2}<Cell ss:StyleID="TableData"><Data ss:Type=[^\<]{1,2000}?>({src_host}[^\<]{1,2000}?)<\/Data><\/Cell>""",
    """<Row>(<Cell ss:StyleID="TableData"><Data ss:Type=[^\<]{1,2000}?>(<\/Cell>|[^\<]{1,2000}?<\/Data><\/Cell>)){3}<Cell ss:StyleID="TableData"><Data ss:Type=[^\<]{1,2000}?>({alert_name}[^\<]{1,2000}?)<\/Data><\/Cell>""",
    """<Row>(<Cell ss:StyleID="TableData"><Data ss:Type=[^\<]{1,2000}?>(<\/Cell>|[^\<]{1,2000}?<\/Data><\/Cell>)){4}<Cell ss:StyleID="TableData"><Data ss:Type=[^\<]{1,2000}?>({time}[^\<]{1,2000}?)<\/Data><\/Cell>""",
    """<Row>(<Cell ss:StyleID="TableData"><Data ss:Type=[^\<]{1,2000}?>(<\/Cell>|[^\<]{1,2000}?<\/Data><\/Cell>)){5}<Cell ss:StyleID="TableData"><Data ss:Type=[^\<]{1,2000}?>({file_path}[^\<]{1,2000}?)<\/Data><\/Cell>""",
    """<Row>(<Cell ss:StyleID="TableData"><Data ss:Type=[^\<]{1,2000}?>(<\/Cell>|[^\<]{1,2000}?<\/Data><\/Cell>)){6}<Cell ss:StyleID="TableData"><Data ss:Type=[^\<]{1,2000}?>({threat_category}[^\<]{1,2000}?)<\/Data><\/Cell>""",
    """<Row>(<Cell ss:StyleID="TableData"><Data ss:Type=[^\<]{1,2000}?>(<\/Cell>|[^\<]{1,2000}?<\/Data><\/Cell>)){13}<Cell ss:StyleID="TableData"><Data ss:Type=[^\<]{1,2000}?>({src_ip}[^\<]{1,2000}?)<\/Data><\/Cell>""",
    """<Row>(<Cell ss:StyleID="TableData"><Data ss:Type=[^\<]{1,2000}?>(<\/Cell>|[^\<]{1,2000}?<\/Data><\/Cell>)){15}<Cell ss:StyleID="TableData"><Data ss:Type=[^\<]{1,2000}?>({domain}[^\<]{1,2000}?)<\/Data><\/Cell>""",

  ]
  DupFields=[ "alert_name->alert_type" ]
}
```