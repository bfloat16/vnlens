# 脚本 IR：opcode 与 args

当前结构为 IR v5。所有游戏引擎从本文件列出的公共 opcode、语义细分和 args 名称中选择；源码分别使用 `Operation`、`Qualifier`、`ArgName` 封闭枚举，不能填写自定义语义字符串。相同含义使用相同名字，不以引擎前缀或原生命令拼写创建另一套名称。旧的 `Operand`、`operands`、token 单值字段和自由参数名已移除，没有兼容别名。

Lua 按已确定的例外保留标准字节码，不映射到游戏引擎的公共 opcode；其原生字段也使用封闭的 `NativeArg`，共享下面的参数结构。

## 0. 统一结构

| 字段 | 格式 | 功能 |
| --- | --- | --- |
| `opcode` | `category`、`operation`、可选 `variant` | 从统一枚举选择具体操作及已验证细分 |
| `opcode.namespace` / `code` | 原生命名空间 / 数字编号 | 与格式版本共同保留源指令身份 |
| `opcode.native_mnemonic` | 可选原生命令名 | 来源信息；Lua 用它显示标准指令名 |
| `args` | 有序 `Arg[]` | 普通指令、表达式 token 与嵌入命令采用同一结构 |
| `Arg.category` / `name` | 从 `ArgName` 推导的分类 / 固定名称 | 不允许引擎自定义或直接复制原生参数名 |
| `Arg.index` | 可选 `u64` | 重复项或未知项的原始序号；例如 `value[0]`、`unknown[2]` |
| `Arg.value` | `{kind, value}` | 保留整数、IEEE 位、文本、原始字节、地址、表达式或参数组 |
| `Arg.span` | 解码后资源内 `{offset, size}` | 保留原字段位置；派生注释使用零长度 |
| `Arg.native_name` | 可选原生名称，允许空字符串 | 仅作来源信息，不改变统一名称 |
| `attributes` | 原生数值元信息 | 保存类型标记、字段编号、模式等编码证据，不代替公共语义 |
| `Value::Group` | 有序 `Arg[]` | 结构化复合参数；子项继续遵循同一命名与格式 |
| `Value::Expression` | 有序 `Token[]` | token 使用同一 Opcode 和 args；保留原求值顺序与原始字节 |
| `Section.raw` | 原始解码字节 | 保存完整内容、填充和未解释字段 |

参数分类与指令分类独立：例如音频命令复用共用 `duration`，条件指令复用存储类 `variable_id`。已验证角色使用固定名称，未验证角色使用 `unknown` 加原始序号；不按文件扩展名、名字相似程度或参数数量猜测语义。重复项按序保留，名称重复不会覆盖内容。

统一的是名称、角色和结构，不强制改写原始数值：秒与引擎时钟、整数与浮点、字节地址与指令编号不可混同。隐含栈参数保持隐含；同一原始指令不拆成假定都会执行的多条指令。`engine_call` 表示保留原生功能，不能视为已完整归一化；尚未确认的行为使用 `unknown`。

| Value 名称 | 功能 |
| --- | --- |
| `nil` / `boolean` | 空值与布尔值 |
| `integer` / `unsigned` | 精确保留有符号与无符号整数 |
| `float32_bits` / `float64_bits` | 保留 IEEE 位，包括 NaN 载荷及负零 |
| `text` / `bytes` | 已解码文本或需原样保留的字节 |
| `code_address` / `data_address` | 解码资源内的绝对字节地址 |
| `instruction_target` | 当前资源内的指令编号 |
| `resource_instruction_target` | 带资源名称和符号的跨资源指令编号 |
| `expression` / `group` | 表达式 token 列表 / 有序参数组 |

每个引擎内部维护完整的原生 opcode 和参数位置映射；有伴随命令表时保留原名作为来源信息，但不把它直接当作 IR 名称。映射入口必须覆盖所有输入：未验证的 opcode 使用 `unknown`，未验证的参数使用 `unknown[index]`，保留原编号、字段值、Span 和原始字节。空字符串、重复字段和扩展字照常占位；若未知布局导致无法确认后续边界，返回明确错误，不猜测长度后跳过。

新增引擎必须复用统一定义；确有新的已验证语义时先扩展枚举和相应表格，再接入格式解析器。格式与原生执行依据写入对应源码注释，不维护引擎映射 CSV。预览继续显示具体 opcode 和 args，不增加分类列。

## 1. 基础运算与共用值

| opcode 名称 | 功能 | 语义说明 |
| --- | --- | --- |
| `add` | 加法 | 运算类型与溢出语义属于引擎 |
| `subtract` | 减法 | 保留原引擎操作数顺序 |
| `multiply` | 乘法 | 运算类型与溢出语义属于引擎 |
| `divide` | 除法 | 舍入和除零行为属于引擎 |
| `power` | 幂运算 | 保留原生数值类型与元方法行为 |
| `remainder` | 余数 | 余数符号规则属于引擎 |
| `negate` | 算术取负 | 不等同于按位取反 |
| `bit_and` | 按位与 | 不等同于逻辑与 |
| `bit_or` | 按位或 | 不等同于逻辑或 |
| `bit_xor` | 按位异或 | 数值宽度属于引擎 |
| `bit_not` | 按位取反 | 不等同于逻辑非 |
| `shift_left` | 左移 | 移位宽度及超宽移位行为属于引擎 |
| `shift_right` | 右移 | logical 补零；arithmetic 扩展符号位 |
| `convert` | 类型转换 | number 不预设为整数 |
| `concatenate` | 拼接值序列 | 范围及类型转换规则由原 VM 定义 |
| `length` | 读取值的长度 | 字符串和容器长度语义由原 VM 定义 |

| args 名称 | 功能 | 值与单位 | 说明 |
| --- | --- | --- | --- |
| `value` | 常量或赋值右侧 | Value | 不把存储编码混入名称 |
| `left` | 二元运算或比较的左操作数 | Value | 按原语义保留操作数顺序 |
| `right` | 二元运算或比较的右操作数 | Value | 按原语义保留操作数顺序 |
| `value_type` | 类型栈或值类型 | 引擎原始类型编号 | Siglus 10=整数 20=字符串；其他类型保留原值 |
| `left_type` | 一元或二元左侧类型 | 引擎原始类型编号 | 与 operator 共同限定运算 |
| `right_type` | 二元右侧类型 | 引擎原始类型编号 | 允许不同左右类型 |
| `operator` | 原生运算选择器 | u8 | 共同 operation 保留在 Opcode |
| `count` | 元素个数 | 原始整数 | 不把 count_minus_one 当实际个数 |
| `byte_count` | 紧随的字节数量 | 字节 | BGI compact write_bytes |
| `mode` | 原生模式字段 | 原始整数 | BGI compiled 访存的 0/非0 分别走4字节/1字节路径；compact push 的模式不同 |
| `flags` | 控制标志 | 原始整数 | BGI compact branch 低3位选择条件且 bit3 选择立即数目标 |
| `duration` | 动画帧时长 | 引擎计时单位 | 不擅自解释为毫秒 |
| `value[index]` | 常量或赋值右侧 | Value | 不把存储编码混入名称 |

## 2. 栈、变量与存储

| opcode 名称 | 功能 | 语义说明 |
| --- | --- | --- |
| `push` | 向求值栈压入常量或地址 | 整数存储宽度保留在源 opcode 和 Span 中 |
| `pop` | 丢弃栈顶值 | 保留原引擎的类型栈选择 |
| `duplicate` | 复制栈顶值或引用组 | 引用组的边界跟随复制 |
| `declare` | 声明存储位置 | 数组长度可能由栈提供 |
| `load` | 读取存储位置的值 | 地址可能隐含在栈上；变量 token 显式带 sigil 和 variable_id |
| `store` | 向目标位置写入值 | 不能混淆写入顺序或检查方式；复合赋值为读取目标再运算并写回 |
| `reference` | 构造变量引用 | 不把引用当作已读取的值 |
| `get_stack_pointer` | 将栈指针压入求值栈 | 栈指针单位及所属栈由引擎定义 |
| `set_stack_pointer` | 用栈顶值设置栈指针 | 不等同于单纯弹出一个普通值 |
| `adjust_stack_pointer` | 按有符号增量调整栈指针 | BGI compact 使用栈存储区字节增量 |
| `get_arguments` | 读取调用参数 | BGI scrctrl._bp 将 count 个栈值按调用顺序整理 |
| `index_begin` | 开始构造索引访问 | 保留表达式 token 顺序 |
| `index_end` | 结束索引访问 | token 值保留原始索引控制字段 |
| `index_separator` | 分隔索引维度 | 不等同于函数参数分隔符 |

| args 名称 | 功能 | 值与单位 | 说明 |
| --- | --- | --- | --- |
| `destination` | 写入目标 | Expression 或 Group 引用 | 不得合并到右侧 value |
| `source` | 读取来源 | Value 或 Group 引用 | 不与写入目标混淆 |
| `variable` | 变量声明目标 | Expression | 与索引 token 的 variable_id 不同 |
| `variable_id` | 变量表编号 | Unsigned | 保留 sigil 区分变量类别 |
| `initial_value` | 变量初始化值 | Integer 或 Float64Bits 或 Expression | 不是当前执行结果 |
| `sigil` | 变量类别前缀 | Text | 原字符 |
| `local_offset` | 栈局部存储区偏移 | 字节 | BGI 从当前栈指针减去偏移 |
| `local_descriptor` | 打包的局部变量描述符 | 原始整数 | BGI compact 低14位偏移且高2位宽度标签 |
| `data_offset` | 引用数据位置 | DataAddress 或原始偏移字段 | Value 类型和所属记录决定坐标系 |
| `width_tag` | 原生数据宽度标签 | 0=1字节;1=2字节;2=4字节 | 只适用于文档列出的 BGI compact 访存指令 |
| `delta` | 栈指针增量 | 有符号字节数 | BGI compact |
| `destination_type` | 写入位置类型 | 引擎原始类型编号 | 目标路径隐含在栈组 |
| `register` | 当前函数中的寄存器编号 | Group 内整数 | 区别于整数立即数 |
| `upvalue` | 当前函数中的 upvalue 编号 | Group 内整数 | 区别于寄存器编号 |
| `function_index` | 当前函数的子函数下标 | Group 内整数 | 区别于全局 function 属性 |
| `constant_index` | 当前函数常量池下标 | Group 内整数 | 附带解析值的 Span 长度为零 |
| `scope` | 变量作用域编码 | 整数 | 所属格式定义含义 |
| `storage` | 变量存储类别编码 | 整数 | 不规范化原枚举值 |
| `dimensions` | 数组维度数量 | 整数 | 随后维度项逐项保留 |
| `initial_length` | 初始化表达式的编码长度 | 整数 | 不等同于运行时值长度 |
| `dimension[index]` | 数组某维的长度 | 整数 | index 标明维度序号 |

## 3. 分支判断、跳转与调用

| opcode 名称 | 功能 | 语义说明 |
| --- | --- | --- |
| `equal` | 相等比较 | 比较类型属于引擎 |
| `not_equal` | 不等比较 | 比较类型属于引擎 |
| `less` | 小于比较 | 有符号性属于引擎 |
| `greater` | 大于比较 | 有符号性属于引擎 |
| `less_equal` | 小于等于比较 | 有符号性属于引擎 |
| `greater_equal` | 大于等于比较 | 有符号性属于引擎 |
| `logical_and` | 逻辑与 | 不声称短路求值 |
| `logical_or` | 逻辑或 | 不声称短路求值 |
| `logical_not` | 逻辑非 | 保留引擎真假值定义 |
| `jump` | 无条件转移 | 目标可以是栈值或符号；不得把字节地址与指令编号混用 |
| `branch` | 按条件转移 | 不同引擎条件编码及分支结构保留在参数中 |
| `call` | 调用子程序 | 参数与返回值约定属于引擎；静态目标不是必需参数 |
| `return` | 从子程序返回 | 具名返回参数保留引擎定义 |
| `halt` | 停止当前解释执行 | 不隐含退出整个应用 |
| `register_exception` | 注册当前异常处理上下文 | 处理目标隐含在 VM 栈上 |
| `unregister_exception` | 移除当前异常处理上下文 | 不等同于抛出异常 |

| args 名称 | 功能 | 值与单位 | 说明 |
| --- | --- | --- | --- |
| `target` | 控制转移或代码地址 | CodeAddress 或符号表达式 | 隐含栈目标不伪造 |
| `resolved_target` | 由符号表解析的目标 | InstructionTarget 或 ResourceInstructionTarget | 原始符号表达式仍保留 |
| `condition` | 分支条件 | 表达式或原生条件选择值 | BGI compiled 的 0/非0 选择条件并非条件表达式本身 |
| `next_branch_target` | 下一条件分支目标 | Group 内 InstructionTarget 或 CodeAddress | WS2 零值哨兵保留整数；YU-RIS descriptor 和 data_offset 原样保留 |
| `end_target` | 分支或循环结束目标 | Group 内 InstructionTarget 或 CodeAddress | 不能直接当字节偏移 |
| `label_id` | 原生跳转标签编号 | 整数 | Siglus 标签表下标可解析为 CodeAddress；ExHIBIT 块编号可解析为 InstructionTarget |
| `label` | 原生标签符号 | Text / Expression | 不自动推断跨资源地址 |
| `callee` | 调用目标或静态求值所得调用路径 | Group 引用或路径 | 派生元信息使用零长度 Span；未知分量不猜测 |
| `argument_count` | 参数描述数量 | u32 | 不限制嵌套层数 |
| `named_argument_count` | 命名参数数量 | u32 | 随后保存对应编号 |
| `return_type` | 调用返回类型 | 引擎原始类型编号 | 可用于选择返回值栈 |
| `return_code` | 原生返回码记录 | Value 或 Group | 保持其原始字段，不把它当地址 |
| `overload` | 原生函数重载 | u32 | 不改写为函数操作码 |
| `descriptor` | 控制转移的原始描述字 | 整数 | 保留与目标独立的打包字段 |
| `instruction` | 指令编号目标 | InstructionTarget | 不与字节地址混用 |
| `conditional_depth` | 条件嵌套层数 | 整数 | 格式元信息；不是解析限制 |
| `loop_depth` | 循环嵌套层数 | 整数 | 格式元信息；不是解析限制 |
| `argument_type[index]` | 原始顺序中的参数类型 | u32 | Siglus FFFFFFFF 后跟嵌套参数列表 |
| `tuple_count[index]` | 嵌套参数描述数量 | u32 | 保留文件顺序 |
| `named_argument[index]` | 命名参数原始编号 | u32 | 顺序与描述表保持一致 |
| `component[index]` | 调用路径的一个分量 | Value | index 标明原始顺序 |
| `choice[index]` | 选项记录 | Group | 内部 command 使用 Expression token 保存完整指令身份和参数 |

## 4. 文本

| opcode 名称 | 功能 | 语义说明 |
| --- | --- | --- |
| `show_text` | 提交脚本文本 | 不假定等待输入或换页行为 |
| `clear_text` | 清除当前消息内容 | 保留动画与等待等原始控制参数 |

| args 名称 | 功能 | 值与单位 | 说明 |
| --- | --- | --- | --- |
| `text` | 字符串或显示文本 | Text 或 Bytes | 不可解码的合法字节保持 Bytes |
| `text_id` | 运行时文本标识 | u32 | 不等于字符串表下标 |
| `message` | 消息或错误消息文本 | Text / Bytes | 消息表内容，不表示执行显示 |
| `title` | 窗口或配置标题 | Text / Bytes | 保留原始文字 |
| `title_length` | 标题编码长度 | 整数 | 由原格式单位决定 |

## 5. 音频

| opcode 名称 | 功能 | 语义说明 |
| --- | --- | --- |
| `play_audio` | 启动音频播放 | 资源与声道定位由格式决定；原编号和参数顺序保留 |
| `stop_audio` | 停止或淡出音频 | 等待与淡出选项由原参数决定 |
| `set_audio_volume` | 设置或渐变音频音量 | 不将原生音量单位换算成假定的百分比 |
| `wait_audio` | 等待音频状态完成 | ExHIBIT 等待音量渐变结束 |
| `control_audio` | 按原生模式控制音频 | 同一 opcode 可按参数选择播放或音量控制；不拆分和伪造执行分支 |

| args 名称 | 功能 | 值与单位 | 说明 |
| --- | --- | --- | --- |
| `channel` | 音频通道或播放实例标识 | 原生字符串或整数 | 不能据此猜测资源文件名 |
| `volume` | 原生音量值 | 整数或浮点数 | 不统一假设为百分比或分贝 |

## 6. 视频

| opcode 名称 | 功能 | 语义说明 |
| --- | --- | --- |
| `play_video` | 启动视频播放 | 保留原生同步和图层生命周期行为 |
| `stop_video` | 停止或退出视频播放 | 保留等待与图层处理参数 |

| args 名称 | 功能 | 值与单位 | 说明 |
| --- | --- | --- | --- |
| 复用 共用值、图像和未知参数 | 使用上表中已确认的角色 | 保留原格式值 | 未确认的参数使用 `unknown[index]`，不创建占位语义 |

## 7. 图像

| opcode 名称 | 功能 | 语义说明 |
| --- | --- | --- |
| `draw_image` | 绘制图像或图层 | 可以携带遮罩和过渡；不推断未核实的参数角色 |

| args 名称 | 功能 | 值与单位 | 说明 |
| --- | --- | --- | --- |
| `resource` | 关联资源名称 | Text / Bytes | 不改写资源路径 |
| `image_frame` | 动画引用的图像帧 | i32 | GAN 原始字段编号另行保留 |
| `frame_count` | 动画帧数量 | 整数 | 不含非帧控制记录 |
| `offset_x` | 图像横向偏移 | 有符号整数 | 保留原坐标系 |
| `offset_y` | 图像纵向偏移 | 有符号整数 | 保留原坐标系 |
| `width` | 图像或配置宽度 | 整数 | 按记录上下文解释 |
| `height` | 图像或配置高度 | 整数 | 按记录上下文解释 |
| `opacity` | 原生不透明度 | 整数 | 像素源数据保持不变 |

## 8. 效果

| opcode 名称 | 功能 | 语义说明 |
| --- | --- | --- |
| `fade` | 启动画面淡入淡出或透明度过渡 | 不能与音频音量渐变混用 |
| `stop_fade` | 结束画面淡入淡出效果 | 保留等待与完成状态参数 |
| `blur` | 应用模糊效果 | 目标与参数由原格式定义 |
| `stop_blur` | 结束模糊效果 | 不等于恢复任意图像状态 |
| `shake` | 启动震屏或图层震动 | 保留原生方向幅度时长等字段 |

| args 名称 | 功能 | 值与单位 | 说明 |
| --- | --- | --- | --- |
| 复用 共用值、图像和未知参数 | 使用上表中已确认的角色 | 保留原格式值 | 未确认的参数使用 `unknown[index]`，不创建占位语义 |

## 9. 引擎运行时

| opcode 名称 | 功能 | 语义说明 |
| --- | --- | --- |
| `engine_call` | 调用已识别的引擎专用功能 | 保留 native_mnemonic 和原参数名；未推断更具体的通用语义 |

| args 名称 | 功能 | 值与单位 | 说明 |
| --- | --- | --- | --- |
| 复用 调用、存储、共用值和未知参数 | 使用上表中已确认的角色 | 保留原格式值 | 未确认的参数使用 `unknown[index]`，不创建占位语义 |

## 10. 数据记录与源信息

| opcode 名称 | 功能 | 语义说明 |
| --- | --- | --- |
| `source_location` | 记录源码位置 | 不改变执行指令位置 |
| `record` | 声明或辅助数据表记录 | 不是可执行指令；namespace 区分表类型 |

| args 名称 | 功能 | 值与单位 | 说明 |
| --- | --- | --- | --- |
| `source_file` | 源码位置的文件名 | Text 或 Bytes | 不等同于目标资源路径 |
| `source_line` | 源码位置的行号 | 原始整数 | 不改变指令 Span |
| `source_path` | 源码路径 | Text / Bytes | 保持原路径内容 |
| `path` | 函数或数据对象的路径 | Text | 保留原内容 |
| `constants` | 常量列表 | Group | 每个子项仍使用统一 Arg |
| `data` | 内联原始字节 | Bytes | byte_count 个字节 |
| `id` | 原生记录或元素编号 | 整数 | 记录上下文确定编号空间 |
| `index` | 原生索引或索引控制值 | 整数 | 不视为代码地址 |
| `name` | 符号或记录名称 | Text / Bytes | 保留大小写与原始内容 |
| `type` | 原生类型标记 | 整数 | 保留格式定义的类型编码 |
| `metadata` | 原生辅助元数据 | Value | 不推断运行时语义 |
| `code` | 原生记录码 | 整数 | 与公共 opcode 区分 |
| `command` | 嵌入命令 | Expression | 使用同一 Opcode 与 args 结构 |
| `command_count` | 命令定义数量 | 整数 | 按表结构解释 |
| `error_count` | 错误消息数量 | 整数 | 按表结构解释 |
| `maximum_variable_id` | 最大变量编号 | 整数 | 原生编号上界 |
| `return_code_count` | 返回码数量 | 整数 | 辅助表字段 |
| `script_count` | 脚本数量 | 整数 | 辅助表字段 |
| `script_id` | 脚本资源编号 | 整数 | 不等同于指令编号 |
| `path_length` | 路径编码长度 | 整数 | 原格式单位 |
| `runtime_flags` | 运行时标志 | 整数 | 保留原位定义 |
| `label_count` | 标签数量 | 整数 | 辅助表字段 |
| `first_label` | 散列表桶的首标签编号 | 整数 | 不能当文件偏移 |
| `name_length` | 名称编码长度 | 整数 | 原格式单位 |
| `name_hash` | 名称哈希值 | 整数 | 保留格式校验算法 |
| `variable_count` | 变量数量 | 整数 | 辅助表字段 |
| `virtual_key` | 虚拟按键编号 | 整数 | 原始键映射 |
| `window_option` | 窗口选项 | 整数 | 保留原始选项值 |
| `word` | 原始指令字或辅助字 | 整数 | 不赋予未验证语义 |
| `reserved` | 保留字段 | Value | 不丢弃原值 |
| `constant[index]` | 一个常量记录 | Value | index 标明常量序号 |
| `reserved[index]` | 保留字段 | Value | 不丢弃原值 |
| `source_stamp[index]` | 源文件时间或标记字段 | 整数 | 按原序号保留 |
| `source_field[index]` | 用途尚未细分的源文件字段 | 整数 | 按原序号保留 |
| `resource_priority[index]` | 资源优先级表原始字段 | Bytes | 保留原顺序 |
| `option[index]` | 原生配置选项 | 整数 | 按原序号保留 |
| `terminator[index]` | 字符串终止字段 | 整数 | AdvHD schema 独立字段及原始编号保留 |

## 11. 未知语义

| opcode 名称 | 功能 | 语义说明 |
| --- | --- | --- |
| `unknown` | 语义尚未确认的原始指令 | 保留边界及数据；不得按空操作执行 |

| args 名称 | 功能 | 值与单位 | 说明 |
| --- | --- | --- | --- |
| `unknown[index]` | 语义尚未确认的参数 | Value | index 必须保留原参数位置或编号 |

## 12. Lua 原生字节码

| opcode 名称 | 功能 | 语义说明 |
| --- | --- | --- |
| `native` | 保留原生字节码指令集 | Lua 专用原生模式；真实名称在 native_mnemonic；不参与公共语义映射 |

| args 名称 | 功能 | 值与单位 | 说明 |
| --- | --- | --- | --- |
| `A`、`B`、`C`、`k`、`vB`、`vC`、`sJ`、`Ax`、`Bx`、`sBx`、`sB`、`sC` | Lua 5.0–5.5 原生字段 | 按版本解释的整数或引用 | `NativeArg` 明确选择；不会改成公共语义名称 |

Lua 的 `native_mnemonic` 保留 `MOVE`、`LOADK`、`IDIV`、`TAILCALL`、`CLOSE` 等标准名称；未知编号显示 `OP_<hex>`。辅助字保留顺序，`EXTRAARG` 与闭包捕获 `MOVE`/`GETUPVAL` 保持原生名称，无 opcode 的 SETLIST 扩展字显示 `.word`。函数描述记录使用 `record/function`，不代表对 Lua 指令进行语义映射。
