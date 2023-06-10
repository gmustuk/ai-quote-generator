import {createAsyncThunk, createSlice} from "@reduxjs/toolkit";
import {httpConfig} from "../shared/utils/http-config";

interface VoteState {
    [votePostId: string]: any;
}

interface VotePayLoad {
    votePostId: string;
    data: string;
    isVote: Date
}

const initialState: VoteState = {};

export const fetchVotesByVotePostId = createAsyncThunk(
    'likes/fetchVotesByVotePostId',
    async (votePostId: string) => {
        const { data } = await httpConfig.get('apis/vote/votePostId/${votePostId}');
        return { votePostId, data };
    }
);

const slice = createSlice({
    name: "votes",
    initialState,
    reducers: {
        addVote: (state, action) => {
            const { votePostId, data, isVote } = action.payload as VotePayLoad;
            state[votePostId] = { data, isVote };
        },
        removeVote: (state, action) => {
            const { votePostId, voteProfileId } = action.payload;
            const votes = state[votePostId];
            const index = votes.findIndex((vote: any) => vote.voteProfileId === voteProfileId);
            if (index >= 0) {
                votes.splice(index, 1);
            }
        }
    },
    extraReducers: (builder) => {
        builder.addCase(fetchVotesByVotePostId.fulfilled, (state,action) => {
            const { votePostId, data } = action.payload as VotePayLoad;
            state[votePostId] = data;
        });
    }
});

export const { addVote, removeVote } = slice.actions;

export default slice.reducer



























