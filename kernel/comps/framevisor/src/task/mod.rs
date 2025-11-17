use ostd::{
    early_println,
    task::{CurrentTask as OstdCurrentTask, Task as OstdTask},
};

pub struct CurrentTask(OstdCurrentTask);

pub struct Task(OstdTask);

impl Task {
    pub fn current() -> Option<CurrentTask> {
        OstdTask::current().map(CurrentTask)
    }

    fn ostd_task(&self) -> &OstdTask {
        &self.0
    }
}

pub fn init_task() {
    early_println!("[framevisor] Initializing task...");
}
