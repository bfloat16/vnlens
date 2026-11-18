struct Camera { right: vec4<f32>, up: vec4<f32>, back: vec4<f32>, projection: vec4<f32>, mode: vec4<f32> }
@group(0) @binding(0) var<uniform> camera: Camera;
struct Output {
    @builtin(position) position: vec4<f32>,
    @location(0) normal: vec3<f32>,
    @location(1) color: vec4<f32>,
    @location(2) barycentric: vec3<f32>,
}
@vertex fn vertex_main(@location(0) position: vec3<f32>, @location(1) normal: vec3<f32>, @location(2) color: vec4<f32>, @builtin(vertex_index) index: u32) -> Output {
    let x = dot(position, camera.right.xyz) + camera.right.w;
    let y = dot(position, camera.up.xyz) + camera.up.w;
    let z = camera.back.w - dot(position, camera.back.xyz);
    var output: Output;
    output.position = vec4<f32>(x * camera.projection.x, y * camera.projection.y, z * camera.projection.z + camera.projection.w, z);
    output.normal = normal;
    output.color = color;
    output.barycentric = vec3<f32>(0.0);
    output.barycentric[index % 3u] = 1.0;
    return output;
}
@fragment fn fragment_main(input: Output) -> @location(0) vec4<f32> {
    let edge = input.barycentric / max(fwidth(input.barycentric), vec3<f32>(0.00001));
    if camera.mode.x > 0.5 {
        if min(edge.x, min(edge.y,edge.z)) > 1.0 { discard; }
        return vec4<f32>(0.48,0.75,0.98,1.0);
    }
    let n = input.normal / max(length(input.normal), 0.00001);
    let light = 0.28 + 0.72 * abs(dot(n, normalize(vec3<f32>(0.4,0.8,0.6))));
    let color = select(vec3<f32>(0.72,0.76,0.84), input.color.rgb, camera.mode.y > 0.5);
    return vec4<f32>(color * light, 1.0);
}
