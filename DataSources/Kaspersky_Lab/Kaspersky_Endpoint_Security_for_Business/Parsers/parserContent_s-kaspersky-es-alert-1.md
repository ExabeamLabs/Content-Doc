#### Parser Content
```Java
{
Name = s-kaspersky-es-alert-1
  Vendor = Kaspersky Lab
  Product = Kaspersky Endpoint Security for Business
  Lms = Splunk
  DataType = "alert"
  TimeFormat =  "MM/dd/yyyy HH:mm:ss"
  Conditions = [ """CEF""","""|KasperskyLab|SecurityCenter|""","""cs3Label=ProductVersion""" ]
  Fields = [
    """Usuario:\s*({domain}[^\\]+)\\+({user}[^\s]+)""",
    """Componente:\s*({product_name}[^\\]+)""",
    """Resultado\\+Descripción:\s*({action}[^\\]+)""",
    """nObjeto:\s*({malware_url}[^\\]+)""",
    """Objeto\\+Tipo:\s*({alert_type}[^\\]+)""",
    """Objeto\\+Nombre:\s*({alert_name}[^\\]+)""",
    """Objeto\\+Adicional:\s*(\s|({additional_info}[^\\]+))""",
    """Fecha de lanzamiento de la base de datos:\s*({time}[^\\]+(a.\s*m.|p.\s*m.))""",
    """dhost=({dest_host}[^\s]+)\s*dst=""",
    """dst=({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})"""
    """cs6=({protocol}[^\s]+)""",
    """Aplicación\\+Nombre:\s*({app}[^\\]+)""",
    """cs4=({src_ip}[^\s]+)\s*cs4Label=AttackerIPv4""",
    """cs7=({src_port}[^\s]+)\s*cs7Label""",
    """cs8=({dest_ip}[^\s]+)\s*cs8Label=""",
    """cs5=({alert_name}.*?)\scs5Label="""
    """cs4=({alert_id}.*?)\scs4Label=TaskId""",
    """CEF:0\|([^\|]+\|){3}({alert_type}[^\|]+)\|({alert_name}[^\|]+)\|({alert_severity}[^\|])"""
	
    ]
}
```