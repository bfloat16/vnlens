# 脚本 IR 规范（v5）

引擎私有字节码共用统一的封闭枚举词汇表：`Operation`（操作码）、`Qualifier`（语义限定符）与 `ArgName`（参数名），不接受自定义语义字符串或引擎前缀命名。PSB 继续遵循项目既有的结构化模型和解析约束。Lua、Squirrel 等有公开规范的开源 VM 不受通用 IR 封闭词汇限制：保留原生指令集、助记符、参数名及类型，使用 `Operation::Native`、`NativeArg::Named` 等开放入口复用展示与导出容器，不强制进行通用语义映射。

共享模型定义于 `vnlens_core::ir`，`vnlens_script::ir` 继续导出同一组类型。PSB、MDF/MZS、Lua、Squirrel 的模型和解析实现在 `vnlens-middleware`。PSB 经归档域打开，保留完整元数据和全部资源；脚本域只消费已解析的场景元数据，不负责 PSB 的封装或字节解析。Lua、Squirrel 由脚本域适配注册与展示。

## 0. 数据模型

| 字段 | 类型 / 结构 | 定义 |
| --- | --- | --- |
| `opcode` | `{category, operation, variant?}` | `Operation`（决定 `category`）与可选 `Qualifier` |
| `opcode.namespace` / `code` | `String` / `u32` | 原生指令命名空间与数值操作码 |
| `opcode.native_mnemonic` | `Option<String>` | 原生助记符；`Operation::Native`（Lua、Squirrel 等）直接展示原生指令名 |
| `args` | `Vec<Arg>` | 指令、表达式 `Token` 与内嵌命令共用的有序参数列表 |
| `Arg.category` / `name` | `Category` / `&'static str` | 由 `ArgName` 唯一推导的分类与标准参数名 |
| `Arg.index` | `Option<u64>` | 索引化参数的原始序号（序列化为 `name[index]`，如 `value[0]`、`unknown[2]`） |
| `Arg.value` | `Value`（`{kind, value}`） | 参数值载荷 |
| `Arg.span` | `Span`（`{offset, size}`） | 解码后资源内的字节区间；派生字段使用 `size = 0` |
| `Arg.native_name` | `Option<String>` | 伴随命令表中的原生参数名（含空串），仅记录来源信息 |
| `attributes` | `Vec<Attribute>`（`{name, value: u64}`） | 原生类型标记、字段编号、模式位等编码属性 |
| `Value::Group` | `Vec<Arg>` | 有序复合参数组，子项递归使用 `Arg` 结构 |
| `Value::Expression` | `Vec<Token>` | 有序表达式序列；每个 `Token` 含 `opcode`、`span`、`args`、`raw` |
| `Section.raw` | `Vec<u8>` | 节区原始解码字节（含对齐填充与未解释数据） |

| `Value` 变体（`kind`） | 载荷类型 | 定义 |
| --- | --- | --- |
| `nil` / `boolean` | `()` / `bool` | 空值 / 布尔值 |
| `integer` / `unsigned` | `i64` / `u64` | 有符号整数 / 无符号整数 |
| `float32_bits` / `float64_bits` | `u32` / `u64` | IEEE 754 原始位模式（精确保留 NaN 载荷与 `-0.0`） |
| `text` / `bytes` | `String` / `Vec<u8>` | 已解码文本 / 原始字节序列 |
| `code_address` / `data_address` | `u64` | 当前解码资源内的代码 / 数据绝对字节偏移 |
| `instruction_target` | `u64` | 当前资源内的目标指令序号（`Instruction.id`） |
| `resource_instruction_target` | `{resource, instruction, symbol}` | 跨资源目标（资源名、目标指令序号、符号名） |
| `expression` / `group` | `Vec<Token>` / `Vec<Arg>` | 表达式 `Token` 序列 / 结构化参数组 |

### 映射准则

1. **分类正交**：`ArgName.category()` 与指令的 `Operation.category()` 相互独立，指令可按语义跨分类复用 `ArgName`（如音频指令使用 `Basic` 类的 `duration`，分支指令使用 `Storage` 类的 `variable_id`）。
2. **无损保真**：原样保留数值单位（引擎帧/时钟 vs 秒）、数值表示（整数 vs 浮点）、寻址坐标系（字节偏移 vs 指令序号）及隐式栈约定；单条原生指令不拆分为多条假定顺序执行的 IR 指令。隐式栈实参通过零长度（`size = 0`）`Expression`（`get_argument` / `get_argument_count` / `get_arguments`，`variant = stack_argument`）标明运行期取栈位置，原始压栈、类型转换与调用指令仍按原顺序保留；各参数表列出的常量类型均允许替换为运行期取栈或求值 `Expression`。
3. **封闭完备**：引擎私有字节码的已验证语义映射为具名枚举项；引擎专属机制映射为 `engine_call`；未验证操作码映射为 `unknown`，未验证参数映射为 `unknown[index]`。有公开规范的开源 VM 可直接保留原生操作与参数词汇；PSB 不适用此例外。未知变长结构若无法确定后续指令边界则直接返回解析错误。
4. **按需伴随解析**：纯文本脚本（如 Escu:de `.c`/`.h`/`.inc` 伪 C 源码）直接走文本解码通道，二进制场景与结构化资源生成 IR。跨文件过程表、消息表或类描述符仅在签名/词法指纹与 ABI 匹配时按需关联，并附加零长度派生语义字段（如 `procedure_id`、`arguments`、`message`），动态参数序列保留符号化 `get_arguments` 而不按运行期计数预分配条目。
5. **结构化与对象化指令**：以序列化对象或表记录组织的脚本（如 rUGP `CRsa`、TJS2 代码对象表）保留原始类标签或对象编号于 `opcode.code` / `record.script_metadata`，助记符保留原生类名、消息名或 VM 助记符。运行时对象偏移保持整数，不冒充文件字节地址；代码区相对偏移换算为资源内绝对 `code_address` 或 `data_address` 并校验边界。类序列化明确不读取的尾部字节以 `padding` 保留，未识别字段或变长结构保持 `unknown` 或直接报错，不用填充掩盖解析缺口。

---

## 1. 基础运算与通用参数（`basic`）

| `operation` | 语义 | 约束与限定（`variant` / 引擎语义） |
| --- | --- | --- |
| `evaluate` | 对表达式求值 | 原表达式可包含读写副作用；不将整个表达式预先归类为赋值 |
| `add` | 加法 | 操作数类型与溢出语义由源 VM 定义 |
| `subtract` | 减法 | 保持源指令的左右操作数顺序 |
| `multiply` | 乘法 | 操作数类型与溢出语义由源 VM 定义 |
| `divide` | 除法 | 整除/浮点与除零行为由源 VM 定义 |
| `power` | 乘方 | 保持源数值类型与元方法语义 |
| `remainder` | 取模 / 求余 | 余数符号规则由源 VM 定义 |
| `negate` | 算术取负 | 一元算术求反（区别于 `bit_not`） |
| `bit_and` | 按位与 | 位运算（区别于 `logical_and`） |
| `bit_or` | 按位或 | 位运算（区别于 `logical_or`） |
| `bit_xor` | 按位异或 | 位宽由源 VM 定义 |
| `bit_not` | 按位取反 | 一元位反（区别于 `logical_not`） |
| `shift_left` | 左移 | 位宽与超界移位语义由源 VM 定义 |
| `shift_right` | 右移 | `variant = logical`（逻辑右移补 0）或 `arithmetic`（算术右移保符号） |
| `convert` | 类型转换 | 目标类型由 `variant`（如 `integer`、`float32`、`float64`、`text`、`number`）标识 |
| `concatenate` | 序列拼接 | 字符串或值序列拼接，转换规则由源 VM 定义 |
| `type_of` | 查询值类型 | 保留源 VM 类型编号 |
| `character_code` / `character_from_code` | 字符与字符编码数值转换 | TJS 按 UTF-16 码元处理，保留空串、零值及截断到码元宽度的原 VM 规则 |
| `is_valid` | 检查对象有效性 | 结果写回原位；非对象值的判断规则由源 VM 定义 |
| `absolute` | 绝对值 | 数值类型及溢出语义由源 VM 定义 |
| `minimum` / `maximum` | 最小／最大值 | 支持隐式栈上的多值参数 |
| `random` | 生成随机值 | 范围、端点和结果类型由原调用约定决定 |
| `pack_color` | 合并颜色通道 | 保留原通道顺序及位宽 |
| `length` | 长度求值 | 字符串或容器长度，由源 VM 定义 |

| `ArgName` | 语义 | `Value` 类型 | 编码与用法说明 |
| --- | --- | --- | --- |
| `value` | 常量值或右值 | 任意 `Value` | 单值操作数 |
| `values` | 动态值序列 | `Group` / `Expression` | 无法静态确定长度时保留取参表达式 |
| `minimum` / `maximum` | 数值范围边界 | 任意 `Value` | 原值或隐式栈引用 |
| `start_time` | 起始时间 | `Integer` / `Unsigned` / `Expression` | 原格式时间单位 |
| `enabled` | 启用状态 | 任意 `Value` | 原状态值或隐式栈引用 |
| `value[index]` | 第 `index` 个值操作数 | 任意 `Value` | 多值序列中的按序操作数 |
| `left` | 二元运算左操作数 | 任意 `Value` | 保持源操作数顺序 |
| `right` | 二元运算右操作数 | 任意 `Value` | 保持源操作数顺序 |
| `value_type` | 值类型编码 | `Integer` / `Unsigned` | 源 VM 类型编号（如 Siglus `10` = int, `20` = str） |
| `left_type` | 左操作数类型编码 | `Integer` / `Unsigned` | 与 `operator` 共同限定一元/二元运算重载 |
| `right_type` | 右操作数类型编码 | `Integer` / `Unsigned` | 二元运算右操作数的源 VM 类型编号 |
| `operator` | 原生算子编号 | `Unsigned` | 源格式内部算子选择码 |
| `count` | 元素或操作数量 | `Integer` / `Unsigned` | 保持源字段值（如 `count - 1` 编码不预加 1） |
| `byte_count` | 字节长度 | `Integer` / `Unsigned` | 后随内联数据的字节数（如 BGI compact `write_bytes`） |
| `mode` | 原生模式码 | `Integer` / `Unsigned` | 指令子模式（如 BGI 访存位宽选择或压栈模式） |
| `flags` | 控制标志位 | `Integer` / `Unsigned` | 原生位域（如 BGI compact `branch` 条件与寻址位） |
| `mask` | 位掩码或由模式限定的掩码索引 | `Unsigned` / `Expression` | 保留原值及所属模式，不预先展开映射 |
| `precedence` | 表达式规约优先级 | `Unsigned` | 保留源 VM 优先级，与图像显示 `priority` 分开 |
| `duration` | 持续时长 | `Integer` / `Unsigned` | 保持源引擎计时单位（帧或时钟刻度） |

---

## 2. 栈、变量与存储（`storage`）

| `operation` | 语义 | 约束与限定（`variant` / 引擎语义） |
| --- | --- | --- |
| `push` | 压栈 | 位宽、值域与地址类别由 `variant`（`integer`、`float32`、`text`、`message`、`return_value`、`local_address`、`code_address` 等）与 `Span` 记录 |
| `pop` | 出栈 | 按源 VM 规则弹出对应类型栈顶元素（`variant` 可取 `many`、`return_value` 等） |
| `duplicate` | 复制栈顶元素 | 复制单值或引用元组 |
| `declare` | 声明变量或数组 | 维度可由字面参数或求值栈提供 |
| `load` | 读取存储单元 | 地址可隐式取自栈，或由 `sigil` + `variable_id` 显式指定；`global` 读取全局对象，`flag` 读取条件或脚本标志 |
| `store` | 写入存储单元 | 复合赋值通过 `variant`（`add_assign`、`bit_or_assign`、`shift_left_assign`、`shift_right_assign`、`return_value` 等）标识读改写或返回值写入语义 |
| `reference` | 构造存储引用 | 生成左值/引用句柄（如 `flag`、`property`、`variable`），不执行解引用求值 |
| `invalidate` | 使对象失效 | 可将操作的布尔结果写回原位 |
| `bind_context` | 绑定闭包上下文对象 | 修改 `destination` 所指闭包的 this 对象，`source` 为新上下文 |
| `get_stack_pointer` | 读取栈指针并压栈 | 栈指针单位与目标栈由源 VM 定义 |
| `set_stack_pointer` | 将栈顶值写入栈指针 | 直接覆写栈指针寄存器 |
| `adjust_stack_pointer` | 相对调整栈指针 | 按有符号偏移增减栈指针 |
| `enter_frame` | 建立调用栈帧 | 保存原帧基址并分配 `count` 个局部槽位 |
| `leave_frame` | 撤销调用栈帧 | 恢复栈顶和上一帧基址，不隐含返回 |
| `get_argument` | 读取调用实参 | `stack_argument` 指示当前调用参数序列中的 `stack_index`；无此限定时读取原 VM 的外层调用帧 |
| `get_argument_count` | 读取调用实参数量 | `stack_argument` 指示当前过程的参数计数槽 |
| `get_arguments` | 提取调用参数帧 | 从栈帧整理 `count` 个调用实参（如 BGI `scrctrl._bp`） |
| `index_begin` | 索引访问起始标记 | 表达式 `Token` 流中的下标构造起点 |
| `index_end` | 索引访问结束标记 | 表达式 `Token` 流中的下标构造终点 |
| `index_separator` | 多维索引分隔符 | 分隔相邻下标维度 |

| `ArgName` | 语义 | `Value` 类型 | 编码与用法说明 |
| --- | --- | --- | --- |
| `destination` | 写入目标 | `Expression` / `Group` / `Value` | 赋值左值或目标位置 |
| `source` | 读取来源 | `Value` / `Group` | 读取源位置或源操作数 |
| `variable` | 声明目标变量 | `Expression` | 变量声明指令的目标表达式 |
| `variable_id` | 变量表编号 | `Unsigned` / `Integer` | 配合 `sigil` 唯一定位变量槽位 |
| `flag_id` | 标志位编号 | `Unsigned` / `Integer` / `Expression` | 脚本标志表或状态位索引 |
| `context_id` | 执行上下文编号 | `Unsigned` / `Integer` / `Expression` | 线程、纤程或子上下文槽位标识 |
| `initial_value` | 初始值 | `Integer` / `Float64Bits` / `Expression` | 声明或表的静态初始值 |
| `sigil` | 变量域前缀符 | `Text` | 源格式变量前缀字符（如 `$`、`#`、`@`） |
| `local_offset` | 局部栈帧字节偏移 | `Integer` / `Unsigned` | 相对当前栈帧基址的偏移量 |
| `local_index` | 局部栈帧槽位偏移 | `Integer` / `Unsigned` | 相对帧基址的元素索引，区别于字节偏移 |
| `local_descriptor` | 打包局部变量描述符 | `Unsigned` | 如 BGI compact：`bits[0..14] = offset, bits[14..16] = width_tag` |
| `data_offset` | 数据区偏移或地址 | `DataAddress` / `Unsigned` | 解码资源内的数据偏移 |
| `width_tag` | 数据位宽标签 | `Unsigned` | BGI compact：`0 = 1B, 1 = 2B, 2 = 4B` |
| `delta` | 栈指针有符号增量 | `Integer` | 栈指针调整字节数 |
| `destination_type` | 目标值类型编码 | `Integer` / `Unsigned` | 写入目标的源 VM 类型编号 |
| `register` | 局部变量/寄存器槽号 | `Integer` / `Unsigned` | 函数局部寄存器下标 |
| `upvalue` | 闭包上值槽号 | `Integer` / `Unsigned` | 函数 upvalue 下标 |
| `function_index` | 子函数原型下标 | `Integer` / `Unsigned` | 当前函数原型表中的子函数索引 |
| `constant_index` | 常量池下标 | `Integer` / `Unsigned` | 当前函数常量池索引（附带解析值使用 `size = 0`） |
| `string_index` | 内嵌字符串表下标 | `Integer` / `Unsigned` / `Expression` | 脚本内嵌字符串表索引（区别于运行期 `text_id`） |
| `scope` | 作用域编码 | `Integer` / `Unsigned` | 源格式变量作用域枚举值 |
| `parent_index` | 父对象编号 | `Integer` | TJS 负值表示无父对象 |
| `reserve_count` | 保留槽位数量 | `Integer` / `Unsigned` | TJS 对象头的变量保留槽数量 |
| `maximum_register_index` | 临时寄存器索引上界 | `Integer` / `Unsigned` | TJS 的 `MaxFrameCount`；寄存器 0 另占一个槽 |
| `argument_base` / `collapse_base` | 调用帧展开参数起点 | `Integer` | 分别保存未命名参数展开起点与具名收集参数槽，保留负值哨兵 |
| `setter_index` / `getter_index` / `super_class_getter_index` | 属性及基类求值对象编号 | `Integer` | TJS 对象表内引用，保留无引用的负值 |
| `storage` | 存储类别编码 | `Integer` / `Unsigned` | 源格式存储类别枚举值 |
| `dimensions` | 数组维度数 | `Integer` / `Unsigned` | 后随 `dimension[index]` 的数量 |
| `initial_length` | 初始值编码长度 | `Integer` / `Unsigned` | 初始化数据在源文件中的编码长度 |
| `dimension[index]` | 第 `index` 维大小 | `Integer` / `Unsigned` | 多维数组各维长度 |

---

## 3. 比较、逻辑与控制流（`control_flow`）

| `operation` | 语义 | 约束与限定（`variant` / 引擎语义） |
| --- | --- | --- |
| `equal` | 相等比较（`==`） | 比较类型与强弱相等规则由 `variant`（如 `strict`）及源 VM 定义 |
| `not_equal` | 不等比较（`!=`） | 比较类型由源 VM 定义 |
| `less` | 小于比较（`<`） | 有符号/无符号语义由源 VM 定义 |
| `greater` | 大于比较（`>`） | 有符号/无符号语义由源 VM 定义 |
| `less_equal` | 小于等于（`<=`） | 有符号/无符号语义由源 VM 定义 |
| `greater_equal` | 大于等于（`>=`） | 有符号/无符号语义由源 VM 定义 |
| `instance_of` | 检查对象类型或继承关系 | TJS 将 `destination` 原值与 `right` 类名比较，结果写回原位，不写条件旗标 |
| `logical_and` | 逻辑与 | 布尔求值（不隐含短路控制流） |
| `logical_or` | 逻辑或 | 布尔求值（不隐含短路控制流） |
| `logical_xor` | 逻辑异或 | 布尔真值异或（区别于 `bit_xor`） |
| `logical_not` | 逻辑非 | 按源 VM 真值规则求反 |
| `jump` | 无条件跳转 | 目标可为字节偏移、指令序号、标签符号或隐式栈顶值 |
| `branch` | 条件分支 | 条件极性可由 `variant`（`zero`、`nonzero`、`error`）或 `condition` 参数指定 |
| `call` | 子程序调用 | 调用约定、实参传递与返回值栈由源 VM 定义 |
| `return` | 子程序返回 | 携带可选返回值或返回码 |
| `halt` | 终止当前脚本执行流 | 停止当前解释器上下文 |
| `show_choices` | 展示并等待选择结果 | 可更新返回值及脚本 PC；`image` 为点击图，`script_file` 为章节选择 |
| `add_choice` | 注册选择项 | 保存文本与选择后的跳转目标；不立即展示选择界面 |
| `register_exception` | 注册异常处理帧 | 在 VM 异常栈压入处理上下文 |
| `unregister_exception` | 注销异常处理帧 | 弹出当前异常处理上下文 |

| `ArgName` | 语义 | `Value` 类型 | 编码与用法说明 |
| --- | --- | --- | --- |
| `target` | 跳转目标 | `CodeAddress` / `InstructionTarget` / `Expression` | 显式编码的目标地址或符号表达式 |
| `resolved_target` | 符号表解析后的目标 | `CodeAddress` / `InstructionTarget` / `ResourceInstructionTarget` | 由标签表或跨资源符号静态解析出的目标（`size = 0`） |
| `condition` | 分支条件或条件选择码 | `Expression` / `Integer` / `Unsigned` | 条件表达式或原生条件判别码 |
| `next_branch_target` | 下一分支子句目标 | `InstructionTarget` / `CodeAddress` / `Integer` | 条件链的假分支目标（零值哨兵保持原整数） |
| `end_target` | 结构块结束目标 | `InstructionTarget` / `CodeAddress` | 分支或循环结构的汇合目标 |
| `label_id` | 标签编号 | `Integer` / `Unsigned` | 标签表索引或块编号 |
| `label_base` | 标签基址编号 | `Integer` / `Unsigned` | 与运行时偏移相加构成实际标签编号 |
| `choice_id` | 选项组标识 | `Integer` / `Unsigned` | 选择点状态标识 |
| `default_choice` | 默认/超时选项编码 | `Integer` / `Unsigned` | 保持源格式编码值（含 `0` 哨兵） |
| `heading_count` | 前导非交互标题数 | `Integer` / `Unsigned` | 选项列表中不参与选择的标题项数 |
| `label` | 标签名称或符号 | `Text` / `Expression` | 原生标签文本或符号表达式 |
| `callee` | 被调目标或静态路径 | `Value` / `Group` | 函数引用或由分量拼接的静态调用路径 |
| `arguments` | 按调用约定排列的实参 | `Group` | 衍生取栈表达式不改写原始压栈指令 |
| `stack_index` | 参数序列中的零基索引 | `Unsigned` | Escu:de 的索引 0 对应计数槽下方第一个值 |
| `argument_count` | 位置参数数量 | `Unsigned` / `Integer` | 实参或参数描述符个数 |
| `named_argument_count` | 命名参数数量 | `Unsigned` / `Integer` | 后随 `named_argument[index]` 的个数 |
| `return_type` | 返回值类型编码 | `Integer` / `Unsigned` | 被调函数的返回类型编号 |
| `return_code` | 原生返回码记录 | `Value` / `Group` | 调用点关联的返回状态描述 |
| `overload` | 函数重载编号 | `Unsigned` / `Integer` | 同名命令的重载形态索引 |
| `descriptor` | 控制流打包描述字 | `Integer` / `Unsigned` | 与目标地址分离的控制标志字 |
| `instruction` | 目标指令序号 | `InstructionTarget` | 显式指令级目标引用 |
| `conditional_depth` | 条件嵌套深度 | `Integer` / `Unsigned` | 源格式记录的静态条件层级 |
| `loop_depth` | 循环嵌套深度 | `Integer` / `Unsigned` | 源格式记录的静态循环层级 |
| `argument_type[index]` | 第 `index` 个参数类型码 | `Unsigned` / `Integer` | 参数类型签名序列（如 Siglus `0xFFFFFFFF` 引导嵌套元组） |
| `tuple_count[index]` | 第 `index` 组嵌套参数数 | `Unsigned` / `Integer` | 嵌套参数列表的元素个数 |
| `named_argument[index]` | 第 `index` 个命名参数 ID | `Unsigned` / `Integer` | 命名参数的原生属性编号 |
| `component[index]` | 调用路径第 `index` 分量 | 任意 `Value` | 链式成员访问路径的各级分量 |
| `choice[index]` | 第 `index` 个选项条目 | `Group` | 单个选项的文本、条件与内嵌 `command` |
| `case[index]` | 第 `index` 个多路分支项 | `Group` | `switch` 分支的匹配值与目标地址对 |

---

## 4. 文本（`text`）

| `operation` | 语义 | 约束与限定（`variant` / 引擎语义） |
| --- | --- | --- |
| `show_text` | 输出显示文本 | 可由 `variant = speaker` 区分角色名；不隐含等待输入或换页 |
| `clear_text` | 清空消息窗口文本 | 保留原生过渡与等待控制参数 |
| `wait_text` | 等待消息继续 | 按原格式执行消息完成与翻页等待 |
| `configure_text` | 配置消息显示状态 | 更新后续文本输出模式或窗口状态，不触发文本输出 |
| `text_line_break` | 文本换行控制 | 保留为控制 token，不替换原始字节 |
| `begin_text_span` / `end_text_span` | 开始 / 结束带语义的字形段 | `speaker` 为姓名段，`ruby` 为旁注段；不推断 Unicode 字符 |
| `end_text` | 消息终止 | 不等同于停止脚本 VM 的 `halt` |
| `append_text_history` | 追加历史文本记录 | 不隐含显示新消息或等待输入 |

| `ArgName` | 语义 | `Value` 类型 | 编码与用法说明 |
| --- | --- | --- | --- |
| `text` | 文本内容 | `Text` / `Bytes` | 非法或非文本字节序列无损保留为 `Bytes` |
| `text_id` | 文本运行期标识 | `Unsigned` / `Integer` | 消息或台词流水号（不等同于字符串池下标） |
| `message_index` | 消息表下标 | `Unsigned` / `Integer` | 当前场景对应的消息表索引 |
| `speaker_id` | 发言者编号 | `Unsigned` / `Integer` | 角色表下标，保留无名角色等特殊编码 |
| `message` | 提示、台词或错误消息 | `Text` / `Bytes` / `Group` / `Expression` | 伴随资源解析结果使用含 `resource` 与 `text` 的零长度 `Group`；内联控制码与字形序列使用 `Expression` |
| `voice_id` | 原生语音资源编号或复合编码 | `Unsigned` / `Expression` | 高位携带的数量或标志保留在原值中 |
| `voice_speaker_id` | 语音角色编号 | `Unsigned` / `Expression` | 与显示用 `speaker_id` 分开，不默认相等 |
| `glyph_id` | 字体内字形编号 | `Unsigned` | 不冒充 Unicode 码点 |
| `character_set` | 原生字符集选择 | `Unsigned` | 如数字输出使用的字形集合 |
| `alignment` | 排版对齐方式 | `Unsigned` | 派生值使用零长度 span；0 左、1 中、2 右 |
| `style_id` | 文本样式编号 | `Unsigned` / `Expression` | 保留源样式表索引 |
| `title` | 窗口或章节标题 | `Text` / `Bytes` | 标题文本内容 |
| `title_length` | 标题编码长度 | `Integer` / `Unsigned` | 源格式记录的标题长度字段 |

---

## 5. 音频（`audio`）

| `operation` | 语义 | 约束与限定（`variant` / 引擎语义） |
| --- | --- | --- |
| `play_audio` | 播放音频 | 音频类别由 `variant`（`music`、`voice`、`ambient`、`looping`、`ambient_voice`）细分 |
| `stop_audio` | 停止或淡出音频 | 声道、类别（`variant`）与淡出参数由 `args` 携带 |
| `set_audio_volume` | 设置或渐变音量 | 保持源格式音量量纲，可由 `variant` 限定通道类别 |
| `wait_audio` | 等待音频状态结束 | `variant` 取 `fade`（等待渐变完成）或 `voice`（等待语音结束）等 |
| `control_audio` | 多模式音频控制 | 单一原生指令按模式参数分派播放/停止/调音 |
| `configure_audio` | 预设音频控制参数 | 配置后续音频指令的默认渐变时长、音效或通道状态 |

| `ArgName` | 语义 | `Value` 类型 | 编码与用法说明 |
| --- | --- | --- | --- |
| `channel` | 音频通道或槽位标识 | `Integer` / `Unsigned` / `Text` | 声道编号或通道名 |
| `volume` | 音量值 | `Integer` / `Unsigned` / `Float32Bits` / `Float64Bits` | 保持源格式原始量纲与范围 |

---

## 6. 视频（`video`）

| `operation` | 语义 | 约束与限定（`variant` / 引擎语义） |
| --- | --- | --- |
| `play_video` | 播放视频 | 同步方式与图层绑定由源参数定义 |
| `stop_video` | 停止视频 | 保留等待与图层清理参数 |

> 视频指令参数直接复用 `image`（如 `resource`、`resource_id`、`offset_x`、`offset_y`、`width`、`height`）、`basic`（如 `mode`、`flags`、`duration`）及 `unknown[index]`。

---

## 7. 图像（`image`）

| `operation` | 语义 | 约束与限定（`variant` / 引擎语义） |
| --- | --- | --- |
| `configure_image` | 更新图层／动画状态 | 修改资源绑定、坐标或显示属性，不隐含提交画面 |
| `draw_image` | 绘制图像或提交图层 | 可携带遮罩、坐标与混合参数 |
| `load_image` | 载入图像至图层/缓冲 | 仅绑定或解码资源，不等同于上屏绘制 |
| `clear_image` | 清除图层或图像槽位 | 释放或重置指定图层状态 |
| `set_image_region` | 设置源裁剪区或目标矩形 | 保留源坐标系与尺寸字段 |
| `set_image_visibility` | 设置图层可见性 | 切换图层渲染开关状态 |
| `capture_image` | 捕获当前画面至缓冲 | 帧缓冲复制操作（非外部文件导出） |

| `ArgName` | 语义 | `Value` 类型 | 编码与用法说明 |
| --- | --- | --- | --- |
| `layer` | 图层选择器 | 任意 `Value` | 名称、位掩码或运行时表达式 |
| `scale_x` / `scale_y` | 横向／纵向缩放值 | 任意 `Value` | 不改变原缩放单位 |
| `rotation` | 旋转角度 | 任意 `Value` | 保留原角度单位 |
| `priority` | 显示优先级 | 任意 `Value` | 原排序值 |
| `resource` | 资源名称或路径 | `Text` / `Bytes` | 保持源脚本记录的字符串 |
| `resource_id` | 资源数值编号 | `Integer` / `Unsigned` | 资源表索引或槽位 ID |
| `image_frame` | 动画帧索引 | `Integer` | 如 Siglus GAN 引用的图元帧号 |
| `frame_count` | 动画总帧数 | `Integer` / `Unsigned` | 帧序列包含的帧记录数 |
| `offset_x` | 水平坐标或偏移 | `Integer` | 源坐标系 X 分量 |
| `offset_y` | 垂直坐标或偏移 | `Integer` | 源坐标系 Y 分量 |
| `width` | 宽度 | `Integer` / `Unsigned` | 图像、区域或视口宽度 |
| `height` | 高度 | `Integer` / `Unsigned` | 图像、区域或视口高度 |
| `origin_x` / `origin_y` | 原点或中心坐标 | `Integer` | 保留相对坐标系 |
| `rect_left` / `rect_top` / `rect_right` / `rect_bottom` | 矩形边界 | `Integer` | 原始左右上下边界，不改写成宽高 |
| `color` | 打包颜色值 | `Unsigned` / `Integer` / `Expression` | 通道顺序由原格式定义 |
| `opacity` | 不透明度 | `Integer` / `Unsigned` | 源格式 Alpha / 不透明度值 |
| `red` / `green` / `blue` | 颜色通道值或偏移量 | `Integer` / `Unsigned` | 保持源格式有符号增量或通道范围 |

---

## 8. 视觉效果（`effect`）

| `operation` | 语义 | 约束与限定（`variant` / 引擎语义） |
| --- | --- | --- |
| `fade` | 画面/图层淡入淡出 | 视觉渐变（音频渐变归入 `audio`） |
| `configure_effect` | 配置效果器参数 | 绑定效果类型与控制参数 |
| `transition` | 执行画面过渡 | 按预设或内联参数执行场景切换合成 |
| `stop_fade` | 终止淡入淡出 | 停止当前渐变过程 |
| `blur` | 应用模糊效果 | 关联目标图层与模糊半径等参数 |
| `stop_blur` | 移除模糊效果 | 关闭模糊滤镜状态 |
| `flash` | 画面闪烁 | 保留颜色与次数，不混同淡入淡出 |
| `shake` | 震屏或图层抖动 | 携带方向、振幅、周期与时长参数 |

| `ArgName` | 语义 | `Value` 类型 | 编码与用法说明 |
| --- | --- | --- | --- |
| `effect_id` | 效果器编号 | 任意 `Value` | 原效果表索引或隐式栈引用 |
| `easing` | 插值曲线编码 | `Integer` / `Unsigned` | 原生缓动类型及方向/周期控制位 |
| `easing_parameter` | 插值附加参数 | `Integer` / `Unsigned` | 缓动曲线拐点、周期或系数 |

---

## 9. 引擎运行时（`runtime`）

| `operation` | 语义 | 约束与限定（`variant` / 引擎语义） |
| --- | --- | --- |
| `save_game` | 保存游戏状态 | 自动／手动存档及画面捕获由源调用约定决定 |
| `engine_call` | 调用引擎专属子系统命令 | 通过 `namespace:code` 与 `native_mnemonic` 保留原生命令身份 |
| `wait` | 阻塞等待条件或时长 | 等待时长与中断条件由源参数定义 |
| `yield` | 让出脚本执行权 | 向宿主循环返回执行状态码 |
| `no_op` | 空操作 | 仅用于已验证无副作用的占位指令（未知指令使用 `unknown`） |
| `set_frame_duration` | 设置帧周期 | 配置渲染/更新循环的时间步长 |
| `mark_seen` | 记录已读或资源解锁状态 | `variant` 取 `image`、`script_file`、`speaker` 或 `conditional` |
| `stop_skip` | 退出快进模式 | 终止当前快进状态 |

---

## 10. 数据记录与源信息（`data`）

| `operation` | 语义 | 约束与限定（`variant`） |
| --- | --- | --- |
| `source_location` | 源码行号或文件定位标记 | 元数据伪指令，不改变执行控制流 |
| `record` | 结构化头部、表或声明记录 | 由 `variant` 标识：`script_metadata`、`function`、`command`、`configuration`、`key_mapping`、`error_message`、`system_error`、`hash_bucket`、`image`、`layer`、`animation`、`frame`、`bytes`、`message_table`、`resource_table`、`label_table`、`constant_table`、`return_table`、`choice_table`、`command_table`、`error_table`、`script_table`、`variable_table`、`configuration_table`、`address_table`、`word_table`、`data_table`、`block_begin`、`block_end` |

| `ArgName` | 语义 | `Value` 类型 | 编码与用法说明 |
| --- | --- | --- | --- |
| `source_file` | 源文件名 | `Text` / `Bytes` | 调试信息记录的源文件名 |
| `source_line` | 源码行号 | `Integer` / `Unsigned` | 调试信息记录的源码行号 |
| `source_path` | 源文件路径 | `Text` / `Bytes` | 调试信息记录的完整源路径 |
| `source_map` | 代码到源码位置映射 | `Group` | 有序 `row[index]`，保留重复的代码位置 |
| `source_offset` | 原生源码位置 | `Integer` / `Unsigned` | TJS 的 UTF-16 码元位置，不换算为行号 |
| `properties` | 对象属性注册表 | `Group` | TJS 表项保存字符串编号、解析名称及待注册到父对象的对象编号 |
| `path` | 对象或函数层级路径 | `Text` | 如 PSB/Lua 对象路径 |
| `constants` | 常量表 | `Group` | 聚合 `constant[index]` 子项 |
| `messages` | 消息表描述符 | `Group` | 消息表元信息与条目集合 |
| `resources` | 资源表描述符 | `Group` | 引用资源名列表或表头信息 |
| `labels` | 标签表描述符 | `Group` | 标签编号与目标地址映射集合 |
| `targets` | 跳转目标地址表 | `Group` | 包含原始偏移与 `CodeAddress` 的表项集合 |
| `return_targets` | 调用返回点表 | `Group` | 调用指令地址与返回恢复地址映射表 |
| `choice_targets` | 选项恢复点表 | `Group` | 选项入口地址表 |
| `command_targets` | 宿主命令恢复点表 | `Group` | 命令返回码与恢复地址映射表 |
| `script_call_targets` | 跨脚本调用恢复点表 | `Group` | 当前脚本内的跨脚本调用恢复地址表 |
| `signature` | 格式魔数与头部签名 | `Bytes` | 完整保留头部签名与填充字节 |
| `string_pool` | 字符串池 | `Group` | 聚合 `string[index]`，保留共享后缀、重复引用与原始字节 |
| `padding` | 对齐与填充字节 | `Bytes` | 记录间非零或零填充字节 |
| `data` | 内联原始数据块 | `Bytes` | 由 `byte_count` 指定长度的原始字节载荷 |
| `id` | 记录或条目编号 | `Integer` / `Unsigned` | 表内条目 ID |
| `index` | 索引或槽位序号 | `Integer` / `Unsigned` | 表项下标或控制索引 |
| `name` | 符号或条目名称 | `Text` / `Bytes` | 原样保留大小写与编码 |
| `type` | 原生类型标记 | `Integer` / `Unsigned` | 格式定义的数据类型码 |
| `metadata` | 附加元数据值 | 任意 `Value` | 格式头部或表项附带的未归类元数据 |
| `procedure_id` | 宿主过程表编号 | `Unsigned` | 独立于原指令 opcode，原生名称保留于 `native_name`，已解析过程名同时作为 `opcode.native_mnemonic` |
| `code` | 原生记录码或代码区描述 | `Integer` / `Unsigned` / `Group` | 数值记录码，或包含字数 `count` 和代码起点的描述组 |
| `command` | 内嵌命令表达式 | `Expression` | 嵌套在记录或选项中的命令 `Token` |
| `command_count` | 命令定义总数 | `Integer` / `Unsigned` | 命令表条目数 |
| `error_count` | 错误定义总数 | `Integer` / `Unsigned` | 错误表条目数 |
| `maximum_variable_id` | 变量编号上界 | `Integer` / `Unsigned` | 头部声明的最大变量 ID |
| `return_code_count` | 返回码总数 | `Integer` / `Unsigned` | 返回码表条目数 |
| `script_count` | 脚本总数 | `Integer` / `Unsigned` | 脚本表条目数 |
| `script_id` | 脚本编号 | `Integer` / `Unsigned` | 脚本表内的资源编号 |
| `path_length` | 路径编码长度 | `Integer` / `Unsigned` | 路径字段长度 |
| `runtime_flags` | 运行时标志字 | `Integer` / `Unsigned` | 头部或记录中的运行时位标志 |
| `label_count` | 标签总数 | `Integer` / `Unsigned` | 标签表条目数 |
| `first_label` | 哈希桶首标签编号 | `Integer` / `Unsigned` | 散列桶链表头部的标签索引 |
| `name_length` | 名称编码长度 | `Integer` / `Unsigned` | 名称字段长度 |
| `name_hash` | 名称哈希值 | `Integer` / `Unsigned` | 源格式记录的符号哈希值 |
| `variable_count` | 变量总数 | `Integer` / `Unsigned` | 变量表条目数 |
| `virtual_key` | 虚拟键码 | `Integer` / `Unsigned` | 键位映射记录的键码值 |
| `window_option` | 窗口配置项 | `Integer` / `Unsigned` | 窗口属性配置值 |
| `word` | 原始字数据 | `Integer` / `Unsigned` | 扩展字或字表元素值 |
| `version` | 格式版本或修订号 | `Unsigned` / `Integer` | 文件内显式版本字段 |
| `state` | 对象状态编码 | `Unsigned` / `Integer` | 原始状态枚举 |
| `rows` / `frames` | 数据行／帧记录集合 | `Group` | 按原始序号保留 |
| `row[index]` / `column[index]` | 表格行／列值 | 任意 `Value` | 原生名称保留于 `native_name`，不将其用作统一参数名 |
| `reserved` | 保留字段 | 任意 `Value` | 格式保留字 |
| `constant[index]` | 第 `index` 个常量项 | 任意 `Value` | 常量表元素 |
| `string[index]` | 第 `index` 个字符串项 | `Group` | 含偏移、文本、终止符等字段的字符串池条目 |
| `reserved[index]` | 第 `index` 个保留字段 | 任意 `Value` | 多项保留字序列 |
| `source_stamp[index]` | 第 `index` 个源文件时间戳/校验字 | `Integer` / `Unsigned` | 源文件头部标记序列 |
| `source_field[index]` | 第 `index` 个源文件头字段 | `Integer` / `Unsigned` | 源文件头部未细分整数字段 |
| `resource_priority[index]` | 第 `index` 个资源优先级项 | `Bytes` | 资源优先级原始记录 |
| `option[index]` | 第 `index` 个配置选项 | `Integer` / `Unsigned` | 配置表整数字段序列 |
| `terminator[index]` | 第 `index` 个终止符字段 | `Integer` / `Unsigned` | 独立存储的字符串终止字节（如 AdvHD WS2 schema） |

---

## 11. 未知语义（`unknown`）

| `operation` | 语义 | 约束与限定 |
| --- | --- | --- |
| `unknown` | 语义未验证的原生指令 | 保留完整指令边界、`namespace:code`、`Span` 与原始参数 |

| `ArgName` | 语义 | `Value` 类型 | 编码与用法说明 |
| --- | --- | --- | --- |
| `unknown[index]` | 第 `index` 个语义未验证参数 | 任意 `Value` | `index` 严格对应原参数序号或原生字段编号 |

---

## 12. 开源 VM 的原生字节码（`native`）

| `operation` | 语义 | 约束与限定 |
| --- | --- | --- |
| `native` | 原生指令集透传模式 | Lua 5.0–5.5、Squirrel 2.2.4 等按已实现的 VM 版本解码；指令名存于 `opcode.native_mnemonic`，不受通用 `Operation` 词表限制，未知操作码展示为 `OP_<HEX>` |

| `ArgName`（`NativeArg`） | 语义 | `Value` 类型 | 编码与用法说明 |
| --- | --- | --- | --- |
| `A`, `B`, `C`, `k`, `vB`, `vC`, `sJ`, `Ax`, `Bx`, `sBx`, `sB`, `sC` | Lua 5.0–5.5 指令位域操作数 | `Integer` / `Unsigned` / `Group` | 按对应 Lua 版本的指令格式解码；关联常量、寄存器、upvalue、子函数或跳转目标封装于 `Group`；`EXTRAARG`、闭包伪指令与无 opcode 扩展字（`.word`）均按原始顺序保留，函数原型头使用 `record`（`variant = function`） |
| `arg0`、`arg1`、`arg2`、`arg3` | Squirrel 原生指令字段 | `Integer` / `Unsigned` | 保留原生字段顺序及其字节区间；常量与分支目标可附加解析值 |
| `NativeArg::Named(name)` | 开放的原生 VM 参数名 | 任意 `Value` | 名称来自原生指令格式，不受上述字段示例或通用 `ArgName` 词表限制；需要时可扩展原生模型，不得改写 VM 语义以适配容器 |
