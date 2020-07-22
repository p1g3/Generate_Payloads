# Generate_Payloads

此模块是我的扫描器中一个单独的module，我将其单独提出来发布于github，使用此模块可以解析json嵌套的参数，无论是GET中的嵌套还是POST中的嵌套，都能够完美的解析，并且会自动识别编码，并将payload进行对应的解码，在拼接时会在编码回去。

最终会输出一个元祖，在索引0的是每一个参数所对应的payload，这个需求我最开始并没有加上，当我真正写扫描器的时候我发现对于SSRF之类的漏洞添加上这个需求是非常合理的，因为你需要获取你每一个参数所对应的随机字符串，并到dnslog中去查询。索引1对应的是每一个key以及其对应的payload。

举个例子：

```json
{"k1":"v1","k2":{"k3":"v2"},"k4":[1,2,3]}
```

对应代码：

```
generate_payload_class('{"k1":"v1","k2":{"k3":"v2"},"k4":[1,2,3]}', 'json', '<payload>').generate_payload()
```

上述的参数，被解析后会输出如下结果：

```
{
    'k1': '{"k1": "<payload>", "k2": {"k3": "v2"}, "k4": [1, 2, 3]}',
    'k2': '{"k1": "v1", "k2": "<payload>", "k4": [1, 2, 3]}',
    'k2.k3': '{"k1": "v1", "k2": {"k3": "<payload>"}, "k4": [1, 2, 3]}',
    'k4': '{"k1": "v1", "k2": {"k3": "v2"}, "k4": "<payload>"}',
    'k4.0': '{"k1": "v1", "k2": {"k3": "v2"}, "k4": ["<payload>", 2, 3]}',
    'k4.1': '{"k1": "v1", "k2": {"k3": "v2"}, "k4": [1, "<payload>", 3]}',
    'k4.2': '{"k1": "v1", "k2": {"k3": "v2"}, "k4": [1, 2, "<payload>"]}'
}
```

而对应的索引为0的字典如下：

```
{
    'k1': '<payload>',
    'k2': '<payload>',
    'k2.k3': '<payload>',
    'k4': '<payload>',
    'k4.0': '<payload>',
    'k4.1': '<payload>',
    'k4.2': '<payload>'
}
```

在主程序中，我还提供了多种真实案例中存在的JSON嵌套以做测试，需要注意的是，此模块并不是专为解析JSON嵌套而生的，即使不嵌套也是可以使用其生成payload。
