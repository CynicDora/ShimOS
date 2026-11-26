"""Closed, trusted NumPy mechanism profiles; no arbitrary code/config loading."""
import re

LEVELS = ('base', 'import', 'data', 'blas')
SIZES_MIB = (8, 32, 64, 128)
WRITE_MODES = ('readonly', 'element', 'sparse', 'many', 'full')
COMPUTE = {'light': (128, 1), 'medium': (256, 4), 'heavy': (512, 16)}


def parse(token):
    if token in (None, '', 'legacy'):
        return None
    if not isinstance(token, str):
        raise ValueError('FULL_PROFILE must be a fixed string')
    parts = token.split(':')
    if len(parts) != 5 or parts[0] != 'v1':
        raise ValueError('expected v1:preload:MiB:write:compute')
    _, preload, mib, write, compute = parts
    if preload not in LEVELS or mib not in tuple(map(str, SIZES_MIB)) or write not in WRITE_MODES or compute not in COMPUTE:
        raise ValueError('profile outside fixed admission catalogue', token)
    size, repeats = COMPUTE[compute]
    return dict(token=token, schema='shimos.numpy.profile.v1', preload=preload,
                array_mib=int(mib), array_bytes=int(mib)*1024**2,
                array_elements=int(mib)*1024**2//8, dtype='float64',
                write_mode=write, compute=compute, matrix_dimension=size,
                repetitions=repeats, thread_budget=1)


def output_name(value):
    name = 'numpy-output.npz' if value is None else value
    if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,95}\.npz', name):
        raise ValueError('output must be one restricted .npz basename')
    return name


def write_plan(profile, page_size, data_address=0):
    """Addresses describe intended stores, never measured COW allocation."""
    count = profile['array_elements']; mode = profile['write_mode']
    if mode == 'readonly':
        start, step, stores = 0, 1, 0
    elif mode == 'element':
        start, step, stores = 0, count, 1
    else:
        step = 1 if mode == 'full' else page_size//8*(64 if mode == 'sparse' else 1)
        start, stores = 0, (count+step-1)//step
    if stores:
        first_page = data_address//page_size
        last_page = (data_address+(start+(stores-1)*step)*8+7)//page_size
        if step*8 >= page_size:
            touched = stores
        else:
            touched = last_page-first_page+1
    else:
        touched = 0
    return dict(mode=mode, start=start, step_elements=step, elements=stores,
                logical_store_bytes=stores*8, page_size=page_size,
                intended_distinct_pages=touched,
                interpretation='logical element stores and address-derived pages; not actual COW-copy bytes')


def expected_state(profile, page_size):
    count = profile['array_elements']; plan = write_plan(profile, page_size)
    total = count*(count-1)//2
    return [float(count), float(total), float(total+plan['elements']),
            float(plan['elements']), float(1 if plan['elements'] else 0),
            float(count-1+(1 if plan['elements'] and (count-1)%plan['step_elements']==0 else 0))]
