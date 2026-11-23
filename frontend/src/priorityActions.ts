export const isTopPriorityAction = (action: { rank: number }) => action.rank <= 10;
