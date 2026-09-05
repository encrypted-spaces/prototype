//! Preparation for direct AIR proofs whose logical rows need padding.

use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, BaseAir};
use p3_matrix::{dense::RowMajorMatrix, Matrix};

/// An explicit contract for turning logical AIR rows into padded trace rows.
///
/// Padding is opt-in because no strategy is valid for every AIR. In particular,
/// [`Self::RepeatLast`] is appropriate only when repeating the final valid trace row
/// produces another valid row and satisfies any wraparound transition constraints.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AirTracePadding {
    /// Repeat the final logical row through the profile-derived padded height.
    RepeatLast,
}

/// A direct AIR paired with its profile-derived padded trace shape.
///
/// The wrapped AIR continues to describe logical rows. Preparation pads its
/// preprocessed trace and the valid main rows returned by
/// [`Self::generate_trace`] according to the explicit [`AirTracePadding`]
/// contract.
pub struct PreparedAir<'a, A> {
    air: &'a A,
    logical_trace_height: usize,
    trace_height: usize,
    padding: AirTracePadding,
}

impl<'a, A> PreparedAir<'a, A> {
    pub(crate) fn new(
        air: &'a A,
        logical_trace_height: usize,
        trace_height: usize,
        padding: AirTracePadding,
    ) -> Self {
        assert!(
            logical_trace_height > 0,
            "a prepared AIR requires at least one logical row"
        );
        assert!(
            trace_height.is_power_of_two() && trace_height >= logical_trace_height,
            "padded trace height must be a power of two at least as large as the logical height"
        );

        Self {
            air,
            logical_trace_height,
            trace_height,
            padding,
        }
    }

    /// Return the number of rows in the padded trace committed by the proof.
    pub fn trace_height(&self) -> usize {
        self.trace_height
    }

    /// Generate logical main rows and pad the resulting valid rows to the padded height.
    ///
    /// Each source item must produce exactly one trace row. Padding copies a
    /// complete valid row rather than asking the callback to recompute duplicate
    /// logical work.
    pub fn generate_trace<T, F, G>(&self, logical_rows: &[T], generate: G) -> RowMajorMatrix<F>
    where
        T: Clone,
        F: Clone + Send + Sync,
        A: BaseAir<F>,
        G: FnOnce(Vec<T>) -> RowMajorMatrix<F>,
    {
        assert_eq!(
            logical_rows.len(),
            self.logical_trace_height,
            "source row count must equal the prepared AIR's logical trace height"
        );
        let trace = generate(logical_rows.to_vec());
        assert_eq!(
            trace.width,
            self.air.width(),
            "generated main trace width must equal the prepared AIR width"
        );
        assert_ne!(
            trace.width, 0,
            "a prepared AIR cannot pad a zero-width main trace"
        );
        assert_eq!(
            trace.height(),
            self.logical_trace_height,
            "generated main trace height must equal the logical trace height"
        );
        pad_matrix(trace, self.trace_height, self.padding)
    }
}

impl<A, F> BaseAir<F> for PreparedAir<'_, A>
where
    A: BaseAir<F>,
    F: Clone + Send + Sync,
{
    fn width(&self) -> usize {
        self.air.width()
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        self.air.preprocessed_trace().map(|trace| {
            if trace.width == 0 {
                return trace;
            }
            assert_eq!(
                trace.height(),
                self.logical_trace_height,
                "preprocessed trace height must equal the logical trace height"
            );
            pad_matrix(trace, self.trace_height, self.padding)
        })
    }

    fn preprocessed_width(&self) -> usize {
        self.air.preprocessed_width()
    }

    fn num_periodic_columns(&self) -> usize {
        self.air.num_periodic_columns()
    }

    fn periodic_columns(&self) -> Vec<Vec<F>> {
        self.air.periodic_columns()
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        self.air.main_next_row_columns()
    }

    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        self.air.preprocessed_next_row_columns()
    }

    fn num_constraints(&self) -> Option<usize> {
        self.air.num_constraints()
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        self.air.max_constraint_degree()
    }

    fn num_public_values(&self) -> usize {
        self.air.num_public_values()
    }
}

impl<AB, A> Air<AB> for PreparedAir<'_, A>
where
    AB: AirBuilder,
    A: Air<AB>,
    AB::F: Clone + Send + Sync,
{
    fn eval(&self, builder: &mut AB) {
        self.air.eval(builder);
    }
}

fn pad_matrix<T: Clone + Send + Sync>(
    mut matrix: RowMajorMatrix<T>,
    trace_height: usize,
    padding: AirTracePadding,
) -> RowMajorMatrix<T> {
    let width = matrix.width;
    assert_ne!(width, 0, "cannot pad a zero-width matrix");
    let last_row = matrix.values[matrix.values.len() - width..].to_vec();
    match padding {
        AirTracePadding::RepeatLast => {
            matrix
                .values
                .reserve((trace_height - matrix.height()) * width);
            while matrix.height() < trace_height {
                matrix.values.extend_from_slice(&last_row);
            }
        }
    }
    matrix
}

#[cfg(test)]
mod tests {
    use super::*;

    struct LogicalAir;

    impl BaseAir<u32> for LogicalAir {
        fn width(&self) -> usize {
            1
        }

        fn preprocessed_trace(&self) -> Option<RowMajorMatrix<u32>> {
            Some(RowMajorMatrix::new(vec![1, 10, 2, 20, 3, 30], 2))
        }

        fn preprocessed_width(&self) -> usize {
            2
        }

        fn num_periodic_columns(&self) -> usize {
            1
        }

        fn periodic_columns(&self) -> Vec<Vec<u32>> {
            vec![vec![7, 8]]
        }
    }

    #[test]
    fn repeat_last_pads_main_and_preprocessed_rows_together() {
        let air = LogicalAir;
        let prepared = PreparedAir::new(&air, 3, 8, AirTracePadding::RepeatLast);
        let trace = prepared.generate_trace(&[4, 5, 6], |rows| {
            assert_eq!(rows, vec![4, 5, 6]);
            RowMajorMatrix::new(rows, 1)
        });

        assert_eq!(trace.values, vec![4, 5, 6, 6, 6, 6, 6, 6]);
        assert_eq!(
            prepared.preprocessed_trace().unwrap().values,
            vec![1, 10, 2, 20, 3, 30, 3, 30, 3, 30, 3, 30, 3, 30, 3, 30]
        );
        assert_eq!(prepared.num_periodic_columns(), 1);
        assert_eq!(prepared.periodic_columns(), vec![vec![7, 8]]);
    }

    #[test]
    #[should_panic(expected = "cannot pad a zero-width matrix")]
    fn zero_width_matrix_is_rejected_explicitly() {
        pad_matrix(
            RowMajorMatrix::new(Vec::<u32>::new(), 0),
            1,
            AirTracePadding::RepeatLast,
        );
    }
}
