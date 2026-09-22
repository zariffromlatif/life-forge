from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation

from .experiment import ExperimentResult


def plot_metrics(
    result: ExperimentResult,
    output_dir: str | Path,
) -> None:
    """Save population, density, and activity plots."""

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    plt.figure(figsize=(10, 5))
    plt.plot(result.generations, result.populations)
    plt.xlabel("Generation")
    plt.ylabel("Population")
    plt.title("Population over Time")
    plt.tight_layout()
    plt.savefig(output_path / "population.png", dpi=150)
    plt.close()

    plt.figure(figsize=(10, 5))
    plt.plot(result.generations, result.densities)
    plt.xlabel("Generation")
    plt.ylabel("Density")
    plt.title("Density over Time")
    plt.tight_layout()
    plt.savefig(output_path / "density.png", dpi=150)
    plt.close()

    plt.figure(figsize=(10, 5))
    plt.plot(result.generations, result.activities)
    plt.xlabel("Generation")
    plt.ylabel("Activity")
    plt.title("Activity over Time")
    plt.tight_layout()
    plt.savefig(output_path / "activity.png", dpi=150)
    plt.close()


def animate_world(
    result: ExperimentResult,
    output_path: str | Path,
    frame_step: int = 5,
    interval: int = 50,
) -> None:
    """
    Create an MP4 animation of the world trajectory.

    frame_step:
        Display every Nth generation.

    interval:
        Delay between displayed frames in milliseconds.
    """

    if frame_step <= 0:
        raise ValueError("frame_step must be positive.")

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    states = result.states[::frame_step]

    fig, ax = plt.subplots(figsize=(8, 8))

    image = ax.imshow(
        states[0],
        interpolation="nearest",
        vmin=0,
        vmax=1,
    )

    ax.set_axis_off()

    def update(frame: int):
        image.set_data(states[frame])
        ax.set_title(
            f"Generation {frame * frame_step}"
        )
        return (image,)

    animation = FuncAnimation(
        fig,
        update,
        frames=len(states),
        interval=interval,
        blit=True,
    )

    animation.save(
        output_path,
        writer="ffmpeg",
        dpi=120,
    )

    plt.close(fig)