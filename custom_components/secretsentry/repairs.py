"""Repairs integration for SecretSentry.

This module provides the repair flow handling for SecretSentry findings.
Each security finding creates a repair issue that users can view and
acknowledge in the Home Assistant repairs dashboard.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from homeassistant.components.repairs import RepairsFlow
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResult

if TYPE_CHECKING:
    from homeassistant.components.repairs import RepairsFlow


class SecretSentryRepairFlow(RepairsFlow):
    """Handler for SecretSentry repair flows.

    This flow allows users to acknowledge security findings. Since the
    findings are informational and require manual remediation, the flow
    simply provides information and allows dismissal.
    """

    def __init__(self, issue_id: str) -> None:
        """Initialize the repair flow.

        Args:
            issue_id: The unique identifier for the repair issue.
        """
        self.issue_id = issue_id
        super().__init__()

    async def async_step_init(
        self, user_input: dict[str, str] | None = None
    ) -> FlowResult:
        """Handle the first step of the repair flow.

        This step shows information about the finding and provides
        options for the user.

        Args:
            user_input: User input from the form, if any.

        Returns:
            FlowResult for the next step or completion.
        """
        return self.async_show_menu(
            step_id="init",
            menu_options=["confirm", "ignore"],
            description_placeholders={"issue_id": self.issue_id},
        )

    async def async_step_confirm(
        self, user_input: dict[str, str] | None = None
    ) -> FlowResult:
        """Handle confirmation that user will fix the issue.

        Args:
            user_input: User input from the form.

        Returns:
            FlowResult completing the flow.
        """
        return self.async_create_entry(
            title="",
            data={},
        )

    async def async_step_ignore(
        self, user_input: dict[str, str] | None = None
    ) -> FlowResult:
        """Handle user choosing to ignore the issue.

        Args:
            user_input: User input from the form.

        Returns:
            FlowResult aborting the flow.
        """
        return self.async_abort(reason="ignored")


async def async_create_fix_flow(
    hass: HomeAssistant,
    issue_id: str,
    data: dict[str, str] | None,
) -> RepairsFlow:
    """Create a repair flow for a SecretSentry issue.

    This function is called by Home Assistant when a user clicks to
    fix an issue in the repairs dashboard.

    Args:
        hass: Home Assistant instance.
        issue_id: The unique identifier for the repair issue.
        data: Additional data associated with the issue.

    Returns:
        A RepairsFlow instance to handle the repair.
    """
    return SecretSentryRepairFlow(issue_id)
