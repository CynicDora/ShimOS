"""Separate cold numerical formulation, not the measured task's matmul path.

Caller supplies the pinned NumPy imported in the private VM. No Python/fork
or dependency qualification is granted by this reference.
"""
import os
from profile_spec import expected_state


def outputs(np, profile):
    # Construct identical mathematical inputs with independent indexing.
    x = np.fromiter((float(i) for i in range(1024)), dtype=np.float64).reshape(32, 32)
    n = profile['matrix_dimension']
    indices = np.arange(n, dtype=np.int64)
    flat = n*indices[:, None]+indices[None, :]
    a = (flat % 31).astype(np.float64)/17.0
    b = (flat % 23).astype(np.float64)/13.0
    # optimize=False uses the contraction implementation instead of np.matmul
    # and is computed once, irrespective of the measured repetition count.
    matrix = np.einsum('ik,kj->ij', a, b, optimize=False)
    total = float(matrix.sum())
    repetitions = profile['repetitions']
    repeat_sums = np.array([total+i/1024 for i in range(repetitions)], dtype=np.float64)
    matrix[0, 0] += (repetitions-1)/1024
    return dict(slice=np.array([[float(x[i,j]) for j in range(1,32,4)] for i in range(0,32,3)]),
                broadcast=np.array([[float(x[i,j])+j for j in range(8)] for i in range(4)]),
                sums=np.array([sum(range(1024)),sum(i for i in range(1024) if i%32%2==0)],dtype=np.float64),
                matmul=matrix, repeat_sums=repeat_sums,
                state_summary=np.array(expected_state(profile,os.sysconf('SC_PAGE_SIZE')),dtype=np.float64))
