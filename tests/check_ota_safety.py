"""Run python3 tests/check_ota_safety.py; requires a C compiler and built image."""
from pathlib import Path
import struct
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / 'main/door_ota.c').read_text()
helper = source[source.index('static bool image_mapping_valid('):source.index('static void update_now(')]
stub = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#define ESP_OK 0
#define ESP_IMAGE_VERIFY 0
#define ESP_LOGE(...) ((void)0)
typedef struct { uint32_t address, size; } esp_partition_t;
typedef struct { uint32_t offset, size; } esp_partition_pos_t;
typedef struct {
    struct { unsigned segment_count; } image;
    struct { uint32_t load_addr; } segments[16];
    uint32_t segment_data[16];
} esp_image_metadata_t;
static int verify_result;
static int esp_image_load(int mode, const esp_partition_pos_t *p, esp_image_metadata_t *m) {
    (void)mode;
    *m = (esp_image_metadata_t){.image.segment_count = 3};
    m->segments[0].load_addr = 0x40220010;
    m->segment_data[0] = p->offset + 16;
    m->segments[1].load_addr = 0x402a2ad0;
    m->segment_data[1] = p->offset + 0x82ad0;
    m->segments[2].load_addr = 0x40100000;
    return verify_result;
}
'''
checks = r'''
int main(void) {
    esp_partition_t p = {.address = 0x20000, .size = 0xe0000};
    assert(image_mapping_valid(&p));
    p.address = 0x100000;
    assert(!image_mapping_valid(&p));
    p.address = 0x120000;
    assert(image_mapping_valid(&p));
    verify_result = -1;
    assert(!image_mapping_valid(&p));
}
'''
with tempfile.TemporaryDirectory() as directory:
    test = Path(directory) / 'check.c'
    binary = Path(directory) / 'check'
    test.write_text(stub + helper + checks)
    subprocess.run(['cc', '-std=c99', '-Wall', '-Wextra', '-Werror', str(test), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)

# Check actual linked image origin and size against both slots.
image = (root / 'build/smart-door-opener.bin').read_bytes()
assert image[0] == 0xe9
slots = []
for line in (root / 'partitions.csv').read_text().splitlines():
    fields = [field.strip() for field in line.split(',')]
    if fields[0] in ('ota_0', 'ota_1'):
        slots.append((int(fields[3], 0), int(fields[4], 0)))
assert len(slots) == 2
for start, size in slots:
    assert len(image) <= size and start + size <= 0x200000
    offset = 8
    for _ in range(image[1]):
        address, length = struct.unpack_from('<II', image, offset)
        offset += 8
        assert offset + length <= len(image)
        if 0x40200000 <= address < 0x40300000:
            if offset == 16:
                assert address == 0x40200000 + ((start + offset) & 0xfffff)
            assert (start & 0xfffff) + offset + length <= 0x100000
        offset += length
print('OTA mapping rejection and built-image slot checks: passed')
